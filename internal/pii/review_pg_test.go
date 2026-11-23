package pii

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// A full pool must not wedge the agent: writes that hold every connection
// and meet an unknown table oid reload the map on their own transaction,
// while the hourly tick waits for a connection without holding the map's
// lock. Before the fix the tick held the lock while waiting, and the writes
// waited for the lock: neither ever moved.
func TestFullPoolDoesNotWedgeReloads(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := postgres.NewPool(ctx, f.agent.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	dict, _ := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict)
	require.NoError(t, classes.Load(ctx, pool))

	// Every connection of the pool held by a transaction.
	txs := make([]pgx.Tx, 2)
	for i := range txs {
		txs[i], err = pool.BeginTx(ctx, pgx.TxOptions{})
		require.NoError(t, err)
	}
	// The tick needs a connection: it waits for one.
	tickDone := make(chan error, 1)
	go func() {
		_, err := classes.Tick(ctx, pool)
		tickDone <- err
	}()
	time.Sleep(200 * time.Millisecond)

	// plain has no classes: its oid is unknown, so each result reloads.
	label := action.Column{Name: "label", TableOID: f.oid(t, "public.plain"), Attnum: 2}
	rows := []map[string]any{{"label": "x"}}
	var wg sync.WaitGroup
	errs := make(chan error, len(txs))
	for _, tx := range txs {
		wg.Go(func() {
			octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
			defer ocancel()
			errs <- obs.Returned(octx, tx, []action.Column{label}, rows)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "a write holding a connection reloads on it")
	}
	for _, tx := range txs {
		require.NoError(t, tx.Rollback(ctx))
	}
	require.NoError(t, <-tickDone, "the tick gets its connection once the writes end")
}

// The same, as writes through the store, with ticks, scans and reads
// running at once on a two-connection pool.
func TestConcurrentUnknownOIDWritesOnAFullPool(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := postgres.NewPool(ctx, f.agent.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	dict, _ := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict)
	store := postgres.NewStore(pool, sqlguard.DefaultLimits(), time.Now).WithReturned(obs.Returned)
	reader := postgres.NewReader(pool, sqlguard.DefaultLimits(), time.Now)
	scan := NewScanner(dict, []ScanSource{{Agent: "bot", DB: pool, Classes: classes, Limits: sqlguard.DefaultLimits()}},
		ScanOptions{}, slog.New(slog.DiscardHandler))
	in := action.Intent{RunID: uuidV7(t), TaskID: uuidV7(t), Text: "touch customers"}
	require.NoError(t, store.StartRun(ctx, in))

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	report := func(err error) {
		if err != nil {
			errs <- err
		}
	}
	for _, id := range []int{1, 2, 3} {
		wg.Go(func() {
			for range 4 {
				// p.label comes from plain, a table with no classes.
				_, err := store.Write(ctx, in, action.OpUpdate,
					`UPDATE customers c SET note = 'n' FROM plain p WHERE c.id = $1 AND p.id = 1 RETURNING c.email, p.label`, []any{id})
				report(err)
			}
		})
	}
	wg.Go(func() {
		for range 4 {
			_, err := classes.Tick(ctx, pool)
			report(err)
		}
	})
	wg.Go(func() {
		for range 2 {
			_, err := scan.Cycle(ctx)
			report(err)
		}
	})
	wg.Go(func() {
		for range 4 {
			res, err := reader.Read(ctx, `SELECT label FROM plain`, nil, action.Statement{})
			if err == nil {
				err = obs.Observe(ctx, pool, res.Columns, res.Rows)
			}
			report(err)
		}
	})
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestScanSkipsAKeylessRelationThatTimesOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// A view too slow to read within the statement timeout.
	f.db.Exec(t, `CREATE VIEW public.slow_v AS SELECT c.email AS mail FROM public.customers c
		CROSS JOIN LATERAL (SELECT pg_sleep(0.3)) s;
		GRANT SELECT ON public.slow_v TO `+f.agent.Role)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	limits := sqlguard.DefaultLimits()
	limits.StatementTimeout = 200 * time.Millisecond
	log, out := newLog()
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: f.pool, Classes: NewMap(slog.New(slog.DiscardHandler)), Limits: limits}},
		ScanOptions{}, log)

	res, err := s.Cycle(ctx)
	require.NoError(t, err, "the slow view is skipped, the cycle commits")
	require.Equal(t, 1, res.Skipped)
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "order7@corp.ee", "")))
	require.Contains(t, out.String(), "pii: skipped a relation in this scan")
	require.Contains(t, out.String(), "public.slow_v")
	require.NotContains(t, out.String(), "corp.ee", "names and counts only")
}

func TestScanWarnsWhenBuildsKeepFailing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	pool, err := postgres.NewPool(context.Background(), f.agent.URL, 1)
	require.NoError(t, err)
	pool.Close() // every cycle fails
	dict, _ := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	log, out := newLog()
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: pool, Classes: NewMap(slog.New(slog.DiscardHandler)), Limits: sqlguard.DefaultLimits()}},
		ScanOptions{}, log)
	for i := range failWarnAfter {
		_, err := s.Cycle(context.Background())
		require.Error(t, err)
		require.Equal(t, i == failWarnAfter-1, strings.Contains(out.String(), "has not been rebuilt"), "cycle %d", i)
	}
}

// A basalt classify that commits between a load's two reads, on a write's
// read-committed transaction: the marks are read first, so the map holds
// the older marks and the next tick reloads the new classes.
func TestClassifyBetweenALoadsReadsIsReloadedAtTheNextTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now().Add(-time.Hour))
	ctx := context.Background()
	m := NewMap(slog.New(slog.DiscardHandler))
	note := ColumnRef{TableOID: f.oid(t, "public.customers"), Attnum: f.attnum(t, "public.customers", "note")}
	var once sync.Once
	m.between = func() {
		once.Do(func() { f.classifyWith(t, time.Now(), map[string]string{"customers.note": guardmodel.EntityOther}) })
	}

	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{}) // read committed, as a write's
	require.NoError(t, err)
	got, err := m.Resolve(ctx, tx, []ColumnRef{note})
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class, "the classes were read after the classify committed")

	reloaded, err := m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.True(t, reloaded, "the marks were read before it: the tick sees the catalog move and reloads")
	reloaded, err = m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.False(t, reloaded, "classes and marks agree again")
	got, err = m.Resolve(ctx, f.pool, []ColumnRef{note})
	require.NoError(t, err)
	require.Equal(t, guardmodel.EntityOther, got[0].EntityType)
}

func TestDictionaryErrorsAreEngineErrors(t *testing.T) {
	t.Parallel()
	err := error(&DictionaryError{err: &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}})
	var pe *pgconn.PgError
	require.False(t, errors.As(err, &pe), "a map reload's Postgres error is not the agent's SQL error")
	err = &DictionaryError{err: pii.ErrDeltaFull}
	require.ErrorIs(t, err, pii.ErrDeltaFull)
}
