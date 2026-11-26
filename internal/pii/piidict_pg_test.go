package pii

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// fixtureSQL is the app schema of these tests (fake values only):
// customers (the agent writes it), nokey (no primary key: paged by ctid),
// orders (a two-column key), a view over customers, and plain, which no
// class names.
const fixtureSQL = `
CREATE TABLE public.customers (id bigint PRIMARY KEY, email text, phone text, name text, note text);
INSERT INTO public.customers VALUES
    (1, 'ada@corp.ee', '5551234', 'Ada Lovelace', 'hi'),
    (2, 'bob@corp.ee', NULL, 'Bob Stone', NULL),
    (3, '', NULL, NULL, NULL);
CREATE TABLE public.nokey (email text);
INSERT INTO public.nokey VALUES ('nk1@corp.ee'), ('nk2@corp.ee'), (NULL);
CREATE TABLE public.orders (a int, b text, email text, PRIMARY KEY (a, b));
INSERT INTO public.orders SELECT g % 3, 'k' || g, 'order' || g || '@corp.ee' FROM generate_series(1, 7) g;
CREATE VIEW public.emails_v AS SELECT email AS mail FROM public.customers;
CREATE TABLE public.plain (id bigint PRIMARY KEY, label text);
INSERT INTO public.plain VALUES (1, 'x');
`

type fixture struct {
	db    *guardtest.DB
	agent *guardtest.Agent
	pool  *pgxpool.Pool
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fixtureSQL)
	a := d.NewAgent(t, "bot", []string{"public.customers"},
		[]string{"public.nokey", "public.orders", "public.emails_v", "public.plain"})
	pool, err := postgres.NewPool(context.Background(), a.URL, 4)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return fixture{db: d, agent: a, pool: pool}
}

// identifiers are the IDENTIFIER columns classify gives (table.column:
// entity type); every other readable column is PUBLIC, except the plain
// table, which stays unclassified (no row).
var identifiers = map[string]string{
	"customers.email": guardmodel.EntityEmail,
	"customers.phone": guardmodel.EntityPhone,
	"customers.name":  guardmodel.EntityPersonName,
	"nokey.email":     guardmodel.EntityEmail,
	"orders.email":    guardmodel.EntityEmail,
	"emails_v.mail":   guardmodel.EntityEmail,
}

// classify writes a class for the readable columns, as basalt classify does.
func (f fixture) classify(t *testing.T, at time.Time) {
	t.Helper()
	f.classifyWith(t, at, nil)
}

// classifyWith is classify with more IDENTIFIER columns (table.column:
// entity type) on top of identifiers.
func (f fixture) classifyWith(t *testing.T, at time.Time, extra map[string]string) {
	t.Helper()
	ctx := context.Background()
	rows, err := f.db.Admin.Query(ctx, `SELECT table_schema, table_name, column_name, data_type
		FROM basalt_meta.pii_readable_columns() WHERE table_name <> 'plain'`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.PIIColumn, error) {
		var c guardmodel.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guardmodel.ClassPublic
		if et, ok := identifiers[c.Table+"."+c.Column]; ok {
			c.Class, c.EntityType = guardmodel.ClassIdentifier, et
		}
		if et, ok := extra[c.Table+"."+c.Column]; ok {
			c.Class, c.EntityType = guardmodel.ClassIdentifier, et
		}
		if c.EntityType == guardmodel.EntityPhone {
			c.PhoneRegion = "EE"
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, f.db.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, f.db.Names, guardmodel.Classification{Columns: cols, At: at})
	}))
}

// oid is a table's oid.
func (f fixture) oid(t *testing.T, table string) uint32 {
	t.Helper()
	var oid uint32
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT $1::regclass::oid`, table).Scan(&oid))
	return oid
}

func newDict(t *testing.T, opts corepii.DictionaryOptions) (*corepii.FuseDictionary, *corepii.Keys) {
	t.Helper()
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(dir+"/"+corepii.KeyFileName, rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	return dict, keys
}

func uuidV7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	require.NoError(t, err)
	return id
}

// logBuffer is a logger whose output a test reads.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newLog() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewTextHandler(b, nil)), b
}

// The query path of the engine: the reader on the agent's pool, then the
// observer, as agent.Service.Query does.
func TestValuesReadAreInTheDictionaryAndTokenizedConsistently(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	obs := NewObserver(NewMap(slog.New(slog.DiscardHandler)), dict).On(pgpii.Classes(f.pool))

	reader := postgres.NewReader(f.pool, sqlguard.DefaultLimits(), time.Now)
	res, err := reader.Read(ctx, `SELECT c.id, c.email, c.phone, c.name, lower(c.email) AS computed, c.note FROM customers c ORDER BY c.id`, nil, action.Statement{})
	require.NoError(t, err)
	require.False(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "ada@corp.ee", "")))
	require.NoError(t, obs.Observe(ctx, resultFields(res.Columns), res.Rows))

	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "ada@corp.ee", "")))
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "bob@corp.ee", "")))
	require.True(t, dict.Contains(corepii.EntityPhone, keys.TypedHash(corepii.EntityPhone, "5551234", "EE")), "the column's phone region normalizes it")
	typ, ok := dict.Lookup(keys.GenericHash("Ada Lovelace"))
	require.True(t, ok)
	require.Equal(t, corepii.EntityPersonName, typ)
	_, ok = dict.Lookup(keys.GenericHash("hi"))
	require.False(t, ok, "a PUBLIC column is not added")
	require.Equal(t, 7, dict.Status().DeltaValues, "two emails, one phone, two two-word names stored both ways; NULL and empty skipped")
}

// resultFields names a result's fields, as internal/app does for the
// observer: a computed column has no ref.
func resultFields(cols []action.Column) []piistore.ResultField {
	out := make([]piistore.ResultField, len(cols))
	for i, c := range cols {
		out[i] = piistore.ResultField{Ref: c.Ref, Key: c.Name}
	}
	return out
}

// returned is obs as the store's returned-rows hook, reading the map in the
// write's transaction, as internal/app wires it.
func returned(obs *Observer) postgres.ReturnedFunc {
	return func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error {
		return obs.Observe(ctx, pgpii.ClassesInTx(pgquerier.Unwrap(tx)), resultFields(cols), rows)
	}
}

// refusingDict fails every add, as a full delta does.
type refusingDict struct{}

func (refusingDict) Add(corepii.EntityType, string, string) error { return corepii.ErrDeltaFull }

func TestWriteReturningValuesAreAddedBeforeCommitAndFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	obs := NewObserver(NewMap(slog.New(slog.DiscardHandler)), dict)
	store := postgres.NewStore(f.pool, sqlguard.DefaultLimits(), time.Now).WithReturned(returned(obs))
	in := action.Intent{RunID: uuidV7(t), TaskID: uuidV7(t), Text: "add a customer"}
	require.NoError(t, store.StartRun(ctx, in))
	res, err := store.Write(ctx, in, action.OpInsert,
		`INSERT INTO customers (id, email, name) VALUES (10, 'cy@corp.ee', 'Cy Young') RETURNING id, email, name`, nil)
	require.NoError(t, err)
	require.Len(t, res.Returning, 1)
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "cy@corp.ee", "")))

	// A value the dictionary cannot take rolls the write back.
	refusing := postgres.NewStore(f.pool, sqlguard.DefaultLimits(), time.Now).
		WithReturned(returned(NewObserver(NewMap(slog.New(slog.DiscardHandler)), refusingDict{})))
	_, err = refusing.Write(ctx, in, action.OpInsert,
		`INSERT INTO customers (id, email) VALUES (11, 'dee@corp.ee') RETURNING email`, nil)
	require.ErrorIs(t, err, corepii.ErrDeltaFull)
	require.NotContains(t, err.Error(), "dee@corp.ee", "errors name no value")
	var n int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(id) FROM customers WHERE id = 11`).Scan(&n))
	require.Zero(t, n, "nothing applied")
}

func TestConcurrentReadsReloadsAndScans(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict).On(pgpii.Classes(f.pool))
	reader := postgres.NewReader(f.pool, sqlguard.DefaultLimits(), time.Now)
	s := NewScanner(dict, []ScanSource{{Agent: "bot", Map: classes, Classes: pgpii.Classes(f.pool), Fields: pgpii.Fields(f.pool, sqlguard.DefaultLimits(), DefaultLoadTimeout)}},
		ScanOptions{}, slog.New(slog.DiscardHandler))
	plain := agentcatalog.FieldRef(f.oid(t, "public.plain"), 2)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 8 {
		wg.Go(func() {
			for range 5 {
				res, err := reader.Read(ctx, `SELECT email, name FROM customers`, nil, action.Statement{})
				if err == nil {
					err = obs.Observe(ctx, resultFields(res.Columns), res.Rows)
				}
				if err == nil {
					_, err = classes.Resolve(ctx, pgpii.Classes(f.pool), []agentstore.FieldRef{plain})
				}
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Go(func() {
		for range 3 {
			if _, err := s.Cycle(ctx); err != nil {
				errs <- err
				return
			}
		}
	})
	wg.Go(func() {
		for range 3 {
			if _, err := classes.Tick(ctx, pgpii.Classes(f.pool)); err != nil {
				errs <- err
				return
			}
		}
	})
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "ada@corp.ee", "")))
	// One load at first use, at most one per tick for the classless table,
	// and the ticks themselves (nothing moved): a handful, never one per read.
	require.LessOrEqual(t, classes.loads.Load(), int64(6))
}
