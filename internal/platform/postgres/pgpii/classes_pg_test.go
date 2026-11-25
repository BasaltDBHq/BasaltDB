package pgpii

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// fixtureSQL is the app schema of these tests (fake values only):
// customers (the agent writes it), nokey (no primary key), orders (a
// two-column key), a view over customers, and plain, which no class names.
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

// ref is a column's field ref.
func (f fixture) ref(t *testing.T, table, column string) agentstore.FieldRef {
	t.Helper()
	var (
		oid uint32
		n   int16
	)
	require.NoError(t, f.db.Admin.QueryRow(context.Background(),
		`SELECT attrelid::oid, attnum FROM pg_attribute WHERE attrelid = $1::regclass AND attname = $2`, table, column).Scan(&oid, &n))
	return agentcatalog.FieldRef(oid, n)
}

// oid is a table's oid.
func (f fixture) oid(t *testing.T, table string) uint32 {
	t.Helper()
	var oid uint32
	require.NoError(t, f.db.Admin.QueryRow(context.Background(), `SELECT $1::regclass::oid`, table).Scan(&oid))
	return oid
}

// counted counts the snapshots read through it: one per map load.
type counted struct {
	*ClassStore
	loads atomic.Int64
}

func (c *counted) Snapshot(ctx context.Context) (piistore.Snapshot, error) {
	c.loads.Add(1)
	return c.ClassStore.Snapshot(ctx)
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

// The snapshot names every class row by its field ref, with the resource
// ResourceOf gives for it, in table oid and attribute number order.
func TestSnapshotReadsTheClassRows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	c := Classes(f.pool)
	s, err := c.Snapshot(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, s.Marks.Fingerprint)
	require.NotEmpty(t, s.Marks.CatalogPrint)
	require.NotNil(t, s.Marks.ClassifiedAt)
	var email piistore.FieldClass
	for i, fc := range s.Fields {
		require.Equal(t, c.ResourceOf(fc.Ref), fc.Resource, "%s", fc.Ref)
		if i > 0 {
			prev, _ := agentcatalog.ParseFieldRef(s.Fields[i-1].Ref)
			cur, _ := agentcatalog.ParseFieldRef(fc.Ref)
			require.True(t, prev.OID < cur.OID || (prev.OID == cur.OID && prev.Attnum < cur.Attnum), "ordered by oid, attnum")
		}
		if fc.Ref == f.ref(t, "public.customers", "email") {
			email = fc
		}
	}
	require.Equal(t, piistore.FieldClass{
		Ref: f.ref(t, "public.customers", "email"), Resource: agentstore.ResourceRef(strconv.FormatUint(uint64(f.oid(t, "public.customers")), 10)),
		Namespace: "public", ResourceName: "customers", Field: "email",
		Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail,
	}, email)
	require.True(t, c.Shared())
	require.False(t, ClassesInTx(f.pool).Shared())
}

func TestMapReloadsWhenClassifiedAtMoves(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	m := pii.NewMap(slog.New(slog.DiscardHandler))
	c := Classes(f.pool)

	// Before the first classify: no catalog row, no class.
	reloaded, err := m.Tick(ctx, c)
	require.NoError(t, err)
	require.True(t, reloaded, "the first tick loads")
	email := f.ref(t, "public.customers", "email")
	ids, err := m.Identifiers(ctx, c)
	require.NoError(t, err)
	require.Empty(t, ids)

	reloaded, err = m.Tick(ctx, c)
	require.NoError(t, err)
	require.False(t, reloaded, "nothing moved")

	f.classify(t, time.Now())
	reloaded, err = m.Tick(ctx, c)
	require.NoError(t, err)
	require.True(t, reloaded, "basalt classify ran: the catalog moved")
	got, err := m.Resolve(ctx, c, []agentstore.FieldRef{email})
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)

	// Only classified_at moves (the same classes again): still a reload.
	f.classify(t, time.Now().Add(time.Minute))
	reloaded, err = m.Tick(ctx, c)
	require.NoError(t, err)
	require.True(t, reloaded)

	// A readable column added moves the live fingerprint.
	f.db.Exec(t, `ALTER TABLE public.plain ADD COLUMN extra text`)
	reloaded, err = m.Tick(ctx, c)
	require.NoError(t, err)
	require.True(t, reloaded)
}

func TestMissingColumnIsUnclassifiedAndWarnedOncePerTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, out := newLog()
	m := pii.NewMap(log)
	c := Classes(f.pool)
	// A column added after classify is in no row: UNCLASSIFIED.
	f.db.Exec(t, `ALTER TABLE public.customers ADD COLUMN secret_word text`)
	ref := f.ref(t, "public.customers", "secret_word")
	for range 3 {
		got, err := m.Resolve(ctx, c, []agentstore.FieldRef{ref})
		require.NoError(t, err)
		require.Equal(t, pii.Unclassified, got[0])
	}
	require.Equal(t, 1, strings.Count(out.String(), "UNCLASSIFIED"), out.String())
	require.Contains(t, out.String(), "field="+string(ref))
	_, err := m.Tick(ctx, c)
	require.NoError(t, err)
	_, err = m.Resolve(ctx, c, []agentstore.FieldRef{ref})
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(out.String(), "UNCLASSIFIED"), "warned again on the next tick")
}

func TestWatchWarnsAboutUnclassifiedColumns(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, out := newLog()
	w := pii.NewWatch("bot", pii.NewMap(log), Classes(f.pool), log)
	require.NoError(t, w.Tick(ctx))
	require.Contains(t, out.String(), "pii: 2 columns unclassified: public.plain.id, public.plain.label")
	require.Contains(t, out.String(), "pii: classification loaded")

	// A column that changed type keeps its class and is reported apart.
	f.db.Exec(t, `ALTER TABLE public.customers ALTER COLUMN note TYPE varchar(40)`)
	got, err := Classes(f.pool).Unclassified(ctx)
	require.NoError(t, err)
	var note []piistore.Unclassified
	for _, u := range got {
		if u.Name == "public.customers.note" {
			note = append(note, u)
		}
	}
	require.Len(t, note, 1, "%v", got)
	require.True(t, note[0].Changed)
}

// TestMapListsSecretsAndTheCatalogFingerprint: describe hides SECRET columns
// and keys its fingerprints on the agent's PII catalog row, so the map lists
// its SECRET columns and that row's fingerprint (empty before the first
// classify), loading first when nothing is loaded.
func TestMapListsSecretsAndTheCatalogFingerprint(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	classes := pii.NewMap(slog.New(slog.DiscardHandler))
	m := classes.On(Classes(f.pool))

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
		if (c.Table == "orders" && c.Column == "email") || (c.Table == "customers" && c.Column == "note") {
			c.Class = guardmodel.ClassSecret
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, f.db.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, f.db.Names, guardmodel.Classification{Columns: cols, At: time.Now()})
	}))
	_, err = classes.Tick(ctx, Classes(f.pool))
	require.NoError(t, err)

	secrets, err = m.Secrets(ctx)
	require.NoError(t, err)
	// customers was created before orders: table oid, then attnum.
	require.Equal(t, []agentstore.FieldRef{f.ref(t, "public.customers", "note"), f.ref(t, "public.orders", "email")}, secrets)
	print1, err := m.CatalogFingerprint(ctx)
	require.NoError(t, err)
	require.Regexp(t, `^[0-9a-f]{64}$`, print1)

	got, err := m.Resolve(ctx, secrets)
	require.NoError(t, err)
	require.Equal(t, guardmodel.ClassSecret, got[0].Class)
}

func TestMapReloadsOnceForANewTablePerTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	log, _ := newLog()
	m := pii.NewMap(log)
	c := &counted{ClassStore: Classes(f.pool)}
	require.NoError(t, m.Load(ctx, c))
	require.EqualValues(t, 1, c.loads.Load())

	// A table created again after the load has a new oid: the first result
	// column from it reloads the map, which then knows its class.
	f.db.Exec(t, `DROP VIEW public.emails_v; DROP TABLE public.nokey;
		CREATE TABLE public.nokey (email text);
		CREATE VIEW public.emails_v AS SELECT email AS mail FROM public.customers;
		GRANT SELECT ON public.nokey, public.emails_v TO `+f.agent.Role)
	f.classify(t, time.Now())
	got, err := m.Resolve(ctx, c, []agentstore.FieldRef{f.ref(t, "public.nokey", "email")})
	require.NoError(t, err)
	require.EqualValues(t, 2, c.loads.Load(), "an unknown table reloads the map")
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class)
	require.Equal(t, guardmodel.EntityEmail, got[0].EntityType)

	// A table with no classes reloads once per tick, not on every query.
	plain := f.ref(t, "public.plain", "label")
	for range 5 {
		got, err = m.Resolve(ctx, c, []agentstore.FieldRef{plain})
		require.NoError(t, err)
		require.Equal(t, guardmodel.ClassUnclassified, got[0].Class)
	}
	require.EqualValues(t, 3, c.loads.Load(), "at most once per table per tick")

	// The next tick lets it reload once more (the marks are unchanged, so
	// the tick itself does not reload).
	reloaded, err := m.Tick(ctx, c)
	require.NoError(t, err)
	require.False(t, reloaded)
	_, err = m.Resolve(ctx, c, []agentstore.FieldRef{plain})
	require.NoError(t, err)
	_, err = m.Resolve(ctx, c, []agentstore.FieldRef{plain})
	require.NoError(t, err)
	require.EqualValues(t, 4, c.loads.Load())

	// A computed column has no source: no reload, no class.
	got, err = m.Resolve(ctx, c, []agentstore.FieldRef{""})
	require.NoError(t, err)
	require.Equal(t, pii.Class{}, got[0])
	require.EqualValues(t, 4, c.loads.Load())
}

// A full pool must not wedge the agent: writes that hold every connection
// and meet an unknown table reload the map on their own transaction, while
// the hourly tick waits for a connection without holding the map's lock.
// Before the fix the tick held the lock while waiting, and the writes
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
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(dir+"/"+corepii.KeyFileName, rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, corepii.DefaultDictionaryOptions(time.Now))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	classes := pii.NewMap(slog.New(slog.DiscardHandler))
	obs := pii.NewObserver(classes, dict)
	require.NoError(t, classes.Load(ctx, Classes(pool)))

	// Every connection of the pool held by a transaction.
	txs := make([]pgx.Tx, 2)
	for i := range txs {
		txs[i], err = pool.BeginTx(ctx, pgx.TxOptions{})
		require.NoError(t, err)
	}
	// The tick needs a connection: it waits for one.
	tickDone := make(chan error, 1)
	go func() {
		_, err := classes.Tick(ctx, Classes(pool))
		tickDone <- err
	}()
	time.Sleep(200 * time.Millisecond)

	// plain has no classes: its table is unknown, so each result reloads.
	label := []piistore.ResultField{{Ref: f.ref(t, "public.plain", "label"), Key: "label"}}
	rows := []map[string]any{{"label": "x"}}
	var wg sync.WaitGroup
	errs := make(chan error, len(txs))
	for _, tx := range txs {
		wg.Go(func() {
			octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
			defer ocancel()
			errs <- obs.Observe(octx, ClassesInTx(tx), label, rows)
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

// A basalt classify that commits between a load's two reads, on a write's
// read-committed transaction: the marks are read first, so the map holds
// the older marks and the next tick reloads the new classes.
func TestClassifyBetweenALoadsReadsIsReloadedAtTheNextTick(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now().Add(-time.Hour))
	ctx := context.Background()
	m := pii.NewMap(slog.New(slog.DiscardHandler))
	note := f.ref(t, "public.customers", "note")

	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{}) // read committed, as a write's
	require.NoError(t, err)
	inTx := ClassesInTx(tx)
	var once sync.Once
	inTx.between = func() {
		once.Do(func() { f.classifyWith(t, time.Now(), map[string]string{"customers.note": guardmodel.EntityOther}) })
	}
	got, err := m.Resolve(ctx, inTx, []agentstore.FieldRef{note})
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	require.Equal(t, guardmodel.ClassIdentifier, got[0].Class, "the classes were read after the classify committed")

	reloaded, err := m.Tick(ctx, Classes(f.pool))
	require.NoError(t, err)
	require.True(t, reloaded, "the marks were read before it: the tick sees the catalog move and reloads")
	reloaded, err = m.Tick(ctx, Classes(f.pool))
	require.NoError(t, err)
	require.False(t, reloaded, "classes and marks agree again")
	got, err = m.Resolve(ctx, Classes(f.pool), []agentstore.FieldRef{note})
	require.NoError(t, err)
	require.Equal(t, guardmodel.EntityOther, got[0].EntityType)
}

// The observer adds the values of a result read through the agent's pool.
func TestObserverAddsValuesThroughThePool(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(dir+"/"+corepii.KeyFileName, rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, corepii.DefaultDictionaryOptions(time.Now))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	obs := pii.NewObserver(pii.NewMap(slog.New(slog.DiscardHandler)), dict).On(Classes(f.pool))
	fields := []piistore.ResultField{{Ref: f.ref(t, "public.customers", "email"), Key: "email"}, {Key: "computed"}}
	rows := []map[string]any{{"email": "ada@corp.ee", "computed": "eve@corp.ee"}}
	require.NoError(t, obs.Observe(ctx, fields, rows))
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "ada@corp.ee", "")))
	require.False(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "eve@corp.ee", "")), "a computed value has no class")
}
