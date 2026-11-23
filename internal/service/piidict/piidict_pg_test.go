package piidict

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/dictfile"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
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
	"slow_v.mail":     guardmodel.EntityEmail,
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

func (f fixture) attnum(t *testing.T, table, column string) int16 {
	t.Helper()
	var n int16
	require.NoError(t, f.db.Admin.QueryRow(context.Background(),
		`SELECT attnum FROM pg_attribute WHERE attrelid = $1::regclass AND attname = $2`, table, column).Scan(&n))
	return n
}

// dictDirs remembers each test dictionary's state directory.
var dictDirs sync.Map

func newDict(t *testing.T, opts pii.DictionaryOptions) (*pii.FuseDictionary, *pii.Keys) {
	t.Helper()
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(dir+"/"+pii.KeyFileName, rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	dictDirs.Store(dict, dir)
	return dict, keys
}

func dict2Dir(t *testing.T, dict *pii.FuseDictionary) string {
	t.Helper()
	dir, ok := dictDirs.Load(dict)
	require.True(t, ok)
	s, ok := dir.(string)
	require.True(t, ok)
	return s
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

func TestMapReloadsWhenClassifiedAtMoves(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	m := NewMap(slog.New(slog.DiscardHandler))

	// Before the first classify: no catalog row, no class.
	reloaded, err := m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.True(t, reloaded, "the first tick loads")
	email := ColumnRef{TableOID: f.oid(t, "public.customers"), Attnum: f.attnum(t, "public.customers", "email")}
	ids, err := m.Identifiers(ctx, f.pool)
	require.NoError(t, err)
	require.Empty(t, ids)

	reloaded, err = m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.False(t, reloaded, "nothing moved")

	f.classify(t, time.Now())
	reloaded, err = m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.True(t, reloaded, "basalt classify ran: the catalog moved")
	got, err := m.Resolve(ctx, f.pool, []ColumnRef{email})
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)

	// Only classified_at moves (the same classes again): still a reload.
	f.classify(t, time.Now().Add(time.Minute))
	reloaded, err = m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.True(t, reloaded)

	// A readable column added moves the live fingerprint.
	f.db.Exec(t, `ALTER TABLE public.plain ADD COLUMN extra text`)
	reloaded, err = m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.True(t, reloaded)
}

func TestMissingColumnIsUnclassifiedAndWarnedOncePerTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, out := newLog()
	m := NewMap(log)
	// A column added after classify is in no row: UNCLASSIFIED.
	f.db.Exec(t, `ALTER TABLE public.customers ADD COLUMN secret_word text`)
	ref := ColumnRef{TableOID: f.oid(t, "public.customers"), Attnum: f.attnum(t, "public.customers", "secret_word")}
	for range 3 {
		got, err := m.Resolve(ctx, f.pool, []ColumnRef{ref})
		require.NoError(t, err)
		require.Equal(t, Unclassified, got[0])
	}
	require.Equal(t, 1, strings.Count(out.String(), "UNCLASSIFIED"), out.String())
	_, err := m.Tick(ctx, f.pool)
	require.NoError(t, err)
	_, err = m.Resolve(ctx, f.pool, []ColumnRef{ref})
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(out.String(), "UNCLASSIFIED"), "warned again on the next tick")
}

// The query path of the engine: the reader on the agent's pool, then the
// observer, as agent.Service.Query does.
func TestValuesReadAreInTheDictionaryAndTokenizedConsistently(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	obs := NewObserver(NewMap(slog.New(slog.DiscardHandler)), dict).On(f.pool)

	reader := postgres.NewReader(f.pool, sqlguard.DefaultLimits(), time.Now)
	res, err := reader.Read(ctx, `SELECT c.id, c.email, c.phone, c.name, lower(c.email) AS computed, c.note FROM customers c ORDER BY c.id`, nil, action.Statement{})
	require.NoError(t, err)
	require.False(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "ada@corp.ee", "")))
	require.NoError(t, obs.Observe(ctx, res.Columns, res.Rows))

	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "ada@corp.ee", "")))
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "bob@corp.ee", "")))
	require.True(t, dict.Contains(pii.EntityPhone, keys.TypedHash(pii.EntityPhone, "5551234", "EE")), "the column's phone region normalizes it")
	typ, ok := dict.Lookup(keys.GenericHash("Ada Lovelace"))
	require.True(t, ok)
	require.Equal(t, pii.EntityPersonName, typ)
	_, ok = dict.Lookup(keys.GenericHash("hi"))
	require.False(t, ok, "a PUBLIC column is not added")
	require.Equal(t, 7, dict.Status().DeltaValues, "two emails, one phone, two two-word names stored both ways; NULL and empty skipped")

	// A value read is now found in free text, with the same token each time.
	tz := pii.NewTokenizer(keys, "", append(pii.PatternDetectors(), pii.NewDictionaryDetector(keys, dict, ""))...)
	first, _, err := tz.Tokenize("Please call Ada Lovelace today.")
	require.NoError(t, err)
	require.NotContains(t, first, "Ada Lovelace")
	second, _, err := tz.Tokenize("Please call Ada Lovelace today.")
	require.NoError(t, err)
	require.Equal(t, first, second)
	tok, err := keys.MakeToken(pii.EntityPersonName, "Ada Lovelace", "")
	require.NoError(t, err)
	require.Contains(t, first, tok.Surface())
}

// refusingDict fails every add, as a full delta does.
type refusingDict struct{}

func (refusingDict) Add(pii.EntityType, string, string) error { return pii.ErrDeltaFull }

func TestWriteReturningValuesAreAddedBeforeCommitAndFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	obs := NewObserver(NewMap(slog.New(slog.DiscardHandler)), dict)
	store := postgres.NewStore(f.pool, sqlguard.DefaultLimits(), time.Now).WithReturned(obs.Returned)
	in := action.Intent{RunID: uuidV7(t), TaskID: uuidV7(t), Text: "add a customer"}
	require.NoError(t, store.StartRun(ctx, in))
	res, err := store.Write(ctx, in, action.OpInsert,
		`INSERT INTO customers (id, email, name) VALUES (10, 'cy@corp.ee', 'Cy Young') RETURNING id, email, name`, nil)
	require.NoError(t, err)
	require.Len(t, res.Returning, 1)
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "cy@corp.ee", "")))

	// A value the dictionary cannot take rolls the write back.
	refusing := postgres.NewStore(f.pool, sqlguard.DefaultLimits(), time.Now).
		WithReturned(NewObserver(NewMap(slog.New(slog.DiscardHandler)), refusingDict{}).Returned)
	_, err = refusing.Write(ctx, in, action.OpInsert,
		`INSERT INTO customers (id, email) VALUES (11, 'dee@corp.ee') RETURNING email`, nil)
	require.ErrorIs(t, err, pii.ErrDeltaFull)
	require.NotContains(t, err.Error(), "dee@corp.ee", "errors name no value")
	var n int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(id) FROM customers WHERE id = 11`).Scan(&n))
	require.Zero(t, n, "nothing applied")
}

func TestScanRebuildsFromEveryKindOfRelation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	log, out := newLog()
	var slept time.Duration
	clock := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: f.pool, Classes: classes, Limits: sqlguard.DefaultLimits()}},
		ScanOptions{
			PageRows: 2, RowsPerSecond: 4, Now: func() time.Time { return clock },
			Sleep: func(_ context.Context, d time.Duration) error { slept += d; clock = clock.Add(d); return nil },
		}, log)

	res, err := s.Cycle(ctx)
	require.NoError(t, err)
	require.Equal(t, 6, res.Columns)
	require.False(t, dict.NeedsBuild())
	require.Zero(t, dict.Status().DeltaValues)
	for _, v := range []string{"ada@corp.ee", "bob@corp.ee", "nk1@corp.ee", "nk2@corp.ee", "order1@corp.ee", "order7@corp.ee"} {
		require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, v, "")), v)
	}
	_, ok := dict.Lookup(keys.GenericHash("Bob Stone"))
	require.True(t, ok)
	// customers 3 + nokey 3 + orders 7 rows, and the view's 3 distinct
	// values: paged two rows at a time and held to 4 rows a second.
	require.EqualValues(t, 16, res.Rows)
	require.Equal(t, time.Duration(res.Rows)*time.Second/4, slept)
	require.Contains(t, out.String(), "pii: dictionary scan")
	require.NotContains(t, out.String(), "corp.ee", "the log carries counts, never values")

	st, ok := dictfile.ReadStatus(dict2Dir(t, dict))
	require.True(t, ok)
	require.EqualValues(t, 16, st.LastScanRows)

	// A deleted value drops out at the next cycle (M51-8).
	f.db.Exec(t, `DELETE FROM public.nokey WHERE email = 'nk2@corp.ee'`)
	_, err = s.Cycle(ctx)
	require.NoError(t, err)
	require.False(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "nk2@corp.ee", "")))
}

func TestScanOverBudgetKeepsThePreviousDictionary(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	src := []ScanSource{{Agent: "bot", DB: f.pool, Classes: classes, Limits: sqlguard.DefaultLimits()}}
	_, err := NewScanner(dict, src, ScanOptions{}, slog.New(slog.DiscardHandler)).Cycle(ctx)
	require.NoError(t, err)
	require.NoError(t, dict.Add(pii.EntityEmail, "delta@corp.ee", ""))

	// A budget for 3 values: the cycle stops, the base and delta stay.
	tiny := NewScanner(dict, src, ScanOptions{MaxMemoryBytes: 3 * bytesPerAddBound}, slog.New(slog.DiscardHandler))
	_, err = tiny.Cycle(ctx)
	require.ErrorIs(t, err, ErrScanOverBudget)
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "order7@corp.ee", "")))
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "delta@corp.ee", "")))
	require.Equal(t, 1, dict.Status().DeltaValues)
}

func TestWatchWarnsAboutUnclassifiedColumns(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, out := newLog()
	w := NewWatch("bot", NewMap(log), f.pool, log)
	require.NoError(t, w.Tick(ctx))
	require.Contains(t, out.String(), "pii: 2 columns unclassified: public.plain.id, public.plain.label")
	require.Contains(t, out.String(), "pii: classification loaded")
}

// TestMapListsSecretsAndTheCatalogFingerprint: describe hides SECRET columns
// and keys its fingerprints on the agent's PII catalog row, so the map lists
// its SECRET columns and that row's fingerprint (empty before the first
// classify), loading first when nothing is loaded.
func TestMapListsSecretsAndTheCatalogFingerprint(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	m := NewMap(slog.New(slog.DiscardHandler)).On(f.pool)

	secrets, err := m.Secrets(ctx)
	require.NoError(t, err)
	require.Empty(t, secrets)
	print0, err := m.CatalogFingerprint(ctx)
	require.NoError(t, err)
	require.Empty(t, print0, "no catalog row before the first classify")

	rows, err := f.db.Admin.Query(ctx, `SELECT table_schema, table_name, column_name, data_type FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.PIIColumn, error) {
		var c guardmodel.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guardmodel.ClassPublic
		if c.Table == "orders" && c.Column == "email" {
			c.Class = guardmodel.ClassSecret
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, f.db.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, f.db.Names, guardmodel.Classification{Columns: cols, At: time.Now()})
	}))
	_, err = m.m.Tick(ctx, f.pool)
	require.NoError(t, err)

	secrets, err = m.Secrets(ctx)
	require.NoError(t, err)
	require.Equal(t, []ColumnRef{{TableOID: f.oid(t, "public.orders"), Attnum: f.attnum(t, "public.orders", "email")}}, secrets)
	print1, err := m.CatalogFingerprint(ctx)
	require.NoError(t, err)
	require.Regexp(t, `^[0-9a-f]{64}$`, print1)

	got, err := m.Resolve(ctx, secrets)
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassSecret, got[0].Class)
}

func TestMapReloadsOnceForANewTableOIDPerTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, _ := newLog()
	m := NewMap(log)
	require.NoError(t, m.Load(ctx, f.pool))
	require.EqualValues(t, 1, m.loads.Load())

	// A table created again after the load has a new oid: the first result
	// column from it reloads the map, which then knows its class.
	f.db.Exec(t, `DROP VIEW public.emails_v; DROP TABLE public.nokey;
		CREATE TABLE public.nokey (email text);
		CREATE VIEW public.emails_v AS SELECT email AS mail FROM public.customers;
		GRANT SELECT ON public.nokey, public.emails_v TO `+f.agent.Role)
	f.classify(t, time.Now())
	ref := ColumnRef{TableOID: f.oid(t, "public.nokey"), Attnum: 1}
	got, err := m.Resolve(ctx, f.pool, []ColumnRef{ref})
	require.NoError(t, err)
	require.EqualValues(t, 2, m.loads.Load(), "an unknown oid reloads the map")
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)
	require.Equal(t, guardmodel.EntityEmail, got[0].EntityType)

	// A table with no classes reloads once per tick, not on every query.
	plain := ColumnRef{TableOID: f.oid(t, "public.plain"), Attnum: 2}
	for range 5 {
		got, err = m.Resolve(ctx, f.pool, []ColumnRef{plain})
		require.NoError(t, err)
		require.Equal(t, guardmodel.ClassUnclassified, got[0].Class)
	}
	require.EqualValues(t, 3, m.loads.Load(), "at most once per oid per tick")

	// The next tick lets it reload once more (the marks are unchanged, so
	// the tick itself does not reload).
	reloaded, err := m.Tick(ctx, f.pool)
	require.NoError(t, err)
	require.False(t, reloaded)
	_, err = m.Resolve(ctx, f.pool, []ColumnRef{plain})
	require.NoError(t, err)
	_, err = m.Resolve(ctx, f.pool, []ColumnRef{plain})
	require.NoError(t, err)
	require.EqualValues(t, 4, m.loads.Load())

	// A computed column has no source: no reload, no class.
	got, err = m.Resolve(ctx, f.pool, []ColumnRef{{}})
	require.NoError(t, err)
	require.Equal(t, Class{}, got[0])
	require.EqualValues(t, 4, m.loads.Load())
}

func TestMapBoundsReloadsAndWarnings(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	m := NewMap(slog.New(slog.DiscardHandler))
	require.NoError(t, m.Load(ctx, f.pool))

	// More unknown oids than the bound, in one result: one reload covers
	// them, and the per-tick sets stop at their bounds.
	refs := make([]ColumnRef, 0, maxReloadOIDs+100)
	for i := range maxReloadOIDs + 100 {
		refs = append(refs, ColumnRef{TableOID: uint32(4_000_000_000 - i), Attnum: 1})
	}
	_, err := m.Resolve(ctx, f.pool, refs)
	require.NoError(t, err)
	require.EqualValues(t, 2, m.loads.Load())
	m.mu.Lock()
	require.Len(t, m.tried, maxReloadOIDs)
	require.Len(t, m.warned, maxWarnedColumns)
	m.mu.Unlock()

	// More unknown oids past the bound: no reload until the next tick.
	_, err = m.Resolve(ctx, f.pool, []ColumnRef{{TableOID: 12345678, Attnum: 1}})
	require.NoError(t, err)
	require.EqualValues(t, 2, m.loads.Load())
}

func TestConcurrentReadsReloadsAndScans(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys := newDict(t, pii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict).On(f.pool)
	reader := postgres.NewReader(f.pool, sqlguard.DefaultLimits(), time.Now)
	s := NewScanner(dict, []ScanSource{{Agent: "bot", DB: f.pool, Classes: classes, Limits: sqlguard.DefaultLimits()}},
		ScanOptions{}, slog.New(slog.DiscardHandler))
	plain := ColumnRef{TableOID: f.oid(t, "public.plain"), Attnum: 2}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 8 {
		wg.Go(func() {
			for range 5 {
				res, err := reader.Read(ctx, `SELECT email, name FROM customers`, nil, action.Statement{})
				if err == nil {
					err = obs.Observe(ctx, res.Columns, res.Rows)
				}
				if err == nil {
					_, err = classes.Resolve(ctx, f.pool, []ColumnRef{plain})
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
			if _, err := classes.Tick(ctx, f.pool); err != nil {
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
	require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, "ada@corp.ee", "")))
	// One load at first use, at most one per tick for the classless table,
	// and the ticks themselves (nothing moved): a handful, never one per read.
	require.LessOrEqual(t, classes.loads.Load(), int64(6))
}
