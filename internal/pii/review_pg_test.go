package pii

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// A full pool must not wedge the agent: writes through the store that hold
// every connection and meet an unknown table reload the map on their own
// transaction, with ticks, scans and reads running at once on a
// two-connection pool.
func TestConcurrentUnknownOIDWritesOnAFullPool(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := postgres.NewPool(ctx, f.agent.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	dict, _ := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict)
	store := postgres.NewStore(pool, sqlguard.DefaultLimits(), time.Now).WithReturned(returned(obs))
	reader := postgres.NewReader(pool, sqlguard.DefaultLimits(), time.Now)
	scan := NewScanner(dict, []ScanSource{{Agent: "bot", DB: pgquerier.Neutralize(pool), ReadOnly: pgquerier.ReadOnlyTx(pool), Map: classes, Classes: pgpii.Classes(pool), Limits: sqlguard.DefaultLimits()}},
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
			_, err := classes.Tick(ctx, pgpii.Classes(pool))
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
				err = obs.Observe(ctx, pgpii.Classes(pool), resultFields(res.Columns), res.Rows)
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
	dict, keys := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	limits := sqlguard.DefaultLimits()
	limits.StatementTimeout = 200 * time.Millisecond
	log, out := newLog()
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: pgquerier.Neutralize(f.pool), ReadOnly: pgquerier.ReadOnlyTx(f.pool), Map: NewMap(slog.New(slog.DiscardHandler)), Classes: pgpii.Classes(f.pool), Limits: limits}},
		ScanOptions{}, log)

	res, err := s.Cycle(ctx)
	require.NoError(t, err, "the slow view is skipped, the cycle commits")
	require.Equal(t, 1, res.Skipped)
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "order7@corp.ee", "")))
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
	dict, _ := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	log, out := newLog()
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: pgquerier.Neutralize(pool), ReadOnly: pgquerier.ReadOnlyTx(pool), Map: NewMap(slog.New(slog.DiscardHandler)), Classes: pgpii.Classes(pool), Limits: sqlguard.DefaultLimits()}},
		ScanOptions{}, log)
	for i := range failWarnAfter {
		_, err := s.Cycle(context.Background())
		require.Error(t, err)
		require.Equal(t, i == failWarnAfter-1, strings.Contains(out.String(), "has not been rebuilt"), "cycle %d", i)
	}
}

func TestDictionaryErrorsAreEngineErrors(t *testing.T) {
	t.Parallel()
	err := error(&DictionaryError{err: &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}})
	var pe *pgconn.PgError
	require.False(t, errors.As(err, &pe), "a map reload's Postgres error is not the agent's SQL error")
	err = &DictionaryError{err: corepii.ErrDeltaFull}
	require.ErrorIs(t, err, corepii.ErrDeltaFull)
}
