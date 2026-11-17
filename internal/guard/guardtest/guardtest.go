// Package guardtest gives tests a fresh Postgres database and role prefix
// per test, against BASALTDB_TEST_POSTGRES_URL, so tests can run in
// parallel on a shared server and clean up after themselves.
package guardtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// EnvURL names the admin connection string of the test server.
const EnvURL = "BASALTDB_TEST_POSTGRES_URL"

// DB is one test database with its own role prefix.
type DB struct {
	Names guard.Names
	// URL is the admin connection string of this database.
	URL   string
	Admin *pgx.Conn
	// base is the test server's admin connection string, name this
	// database's name, and template the database Recreate copies (empty
	// for New).
	base, name, template string
}

// New creates a database bt_<rand> and the prefix bt<rand>. Cleanup drops
// the database and every role with the prefix. Skips without EnvURL.
func New(t *testing.T) *DB {
	t.Helper()
	return newDB(t, testBase(t), randomHex(t), "")
}

// NewRecreatable is New for a database that Recreate can drop and create
// again, as a person does who removes a Postgres container and starts a
// new one from the same image: same database name, same roles, and
// basalt_meta at the same schema oid. Postgres hands out the same oids in
// two clusters made the same way; within one server, a template that
// holds the (empty) basalt_meta schema, owned by the guard role, gives
// every copy that oid.
func NewRecreatable(t *testing.T) *DB {
	t.Helper()
	base := testBase(t)
	suffix := randomHex(t)
	names := guard.Names{Prefix: "bt" + suffix}
	tpl := "bt_" + suffix + "_tpl"
	ctx := context.Background()
	server, err := pgdial.Connect(ctx, base)
	require.NoError(t, err)
	// Plain SQL: test fixture DDL on generated names.
	_, err = server.Exec(ctx, "CREATE DATABASE "+tpl)
	require.NoError(t, err)
	_ = server.Close(ctx)
	c, err := pgdial.Connect(ctx, dbURL(t, base, tpl))
	require.NoError(t, err)
	guardRole := pgx.Identifier{names.Guard()}.Sanitize()
	_, err = c.Exec(ctx, "CREATE ROLE "+guardRole+" NOLOGIN")
	require.NoError(t, err)
	_, err = c.Exec(ctx, "CREATE SCHEMA basalt_meta AUTHORIZATION "+guardRole)
	require.NoError(t, err)
	_ = c.Close(ctx)

	d := newDB(t, base, suffix, tpl)
	// Registered after newDB's cleanup, so it runs first: the template's
	// schema is owned by the guard role, which is dropped after it.
	t.Cleanup(func() { dropDatabase(t, base, tpl) })
	return d
}

// Recreate drops the database and creates it again from its template:
// the guard and the app tables are gone, the roles stay, and a new
// install puts basalt_meta at the same schema oid. Connections to the old
// database are closed. Only for a DB from NewRecreatable.
func (d *DB) Recreate(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, d.template, "Recreate needs a DB from NewRecreatable")
	before := d.schemaOID(t)
	_ = d.Admin.Close(context.Background())
	dropDatabase(t, d.base, d.name)
	createDatabase(t, d.base, d.name, d.template)
	d.Admin = d.connect(t, d.URL)
	require.Equal(t, before, d.schemaOID(t), "the recreated basalt_meta has the old schema oid, or the test proves nothing")
}

// schemaOID is the oid of the basalt_meta schema.
func (d *DB) schemaOID(t *testing.T) uint32 {
	t.Helper()
	var oid uint32
	// Plain SQL: a catalog read for a fixture check.
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = 'basalt_meta'`).Scan(&oid))
	return oid
}

func testBase(t *testing.T) string {
	t.Helper()
	base := os.Getenv(EnvURL)
	if base == "" {
		t.Skip(EnvURL + " not set")
	}
	return base
}

func dbURL(t *testing.T, base, name string) string {
	t.Helper()
	u, err := url.Parse(base)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

// createDatabase creates name, from template when one is given.
func createDatabase(t *testing.T, base, name, template string) {
	t.Helper()
	ctx := context.Background()
	server, err := pgdial.Connect(ctx, base)
	require.NoError(t, err)
	defer server.Close(ctx)
	create := "CREATE DATABASE " + name
	if template != "" {
		create += " TEMPLATE " + template
	}
	// Plain SQL: test fixture DDL on a generated name.
	_, err = server.Exec(ctx, create)
	require.NoError(t, err)
	// Tests assert timestamps as Postgres prints them, so the database
	// prints in UTC whatever TimeZone the test server was initialized with.
	_, err = server.Exec(ctx, "ALTER DATABASE "+name+" SET TimeZone TO 'UTC'")
	require.NoError(t, err)
}

func dropDatabase(t *testing.T, base, name string) {
	t.Helper()
	ctx := context.Background()
	server, err := pgdial.Connect(ctx, base)
	if err != nil {
		t.Errorf("drop database connect: %v", err)
		return
	}
	defer server.Close(ctx)
	if _, err := server.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
		t.Errorf("drop database %s: %v", name, err)
	}
}

// newDB creates the database bt_<suffix> (from template when given) and
// the prefix bt<suffix>, and drops both on cleanup.
func newDB(t *testing.T, base, suffix, template string) *DB {
	t.Helper()
	dbName := "bt_" + suffix
	prefix := "bt" + suffix
	createDatabase(t, base, dbName, template)
	d := &DB{Names: guard.Names{Prefix: prefix}, URL: dbURL(t, base, dbName), base: base, name: dbName, template: template}
	d.Admin = d.connect(t, d.URL)

	t.Cleanup(func() {
		ctx := context.Background()
		_ = d.Admin.Close(ctx)
		dropDatabase(t, base, dbName)
		server, err := pgdial.Connect(ctx, base)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer server.Close(ctx)
		// Agent roles first: they are members of the group.
		rows, err := server.Query(ctx, `SELECT rolname::text FROM pg_roles WHERE rolname LIKE $1
			ORDER BY (rolname LIKE $2) DESC, rolname`, prefix+`\_%`, prefix+`\_agent\_%`)
		if err != nil {
			t.Errorf("cleanup list roles: %v", err)
			return
		}
		roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Errorf("cleanup list roles: %v", err)
			return
		}
		for _, r := range roles {
			if _, err := server.Exec(ctx, "DROP ROLE "+pgx.Identifier{r}.Sanitize()); err != nil {
				t.Errorf("cleanup drop role %s: %v", r, err)
			}
		}
	})
	return d
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func (d *DB) connect(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	c, err := pgdial.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// Exec runs fixture SQL as the admin.
func (d *DB) Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	_, err := d.Admin.Exec(context.Background(), sql, args...)
	require.NoError(t, err)
}

// Init plans and applies basalt init for spec in one transaction.
func (d *DB) Init(t *testing.T, spec guard.AgentSpec) {
	t.Helper()
	require.NoError(t, d.TryInit(spec))
}

// TryInit is Init returning the error. Roles are cluster-wide, so parallel
// test packages creating agent roles can make Postgres report a deadlock
// (40P01) on the shared role catalog; the transaction rolled back, so the
// plan is rebuilt and applied again.
func (d *DB) TryInit(spec guard.AgentSpec) error {
	ctx := context.Background()
	return RetryDeadlock(func() error {
		s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, Agent: spec})
		if err != nil {
			return err
		}
		return pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return s.Apply(ctx, tx) })
	})
}

// deadlockAttempts bounds RetryDeadlock.
const deadlockAttempts = 5

// RetryDeadlock runs fn again, with a short growing pause, while it fails
// with a Postgres deadlock (SQLSTATE 40P01). Any other result returns at once.
func RetryDeadlock(fn func() error) error {
	var err error
	for attempt := 1; attempt <= deadlockAttempts; attempt++ {
		err = fn()
		if SQLState(err) != "40P01" {
			return err
		}
		time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
	}
	return err
}

// envTestMigrations is set (with t.Setenv) while a test's own migrations
// are appended, which also keeps that test from running in parallel.
const envTestMigrations = "BASALTDB_TEST_MIGRATIONS"

// WithMigrations appends test-only versions after the build's own for the
// rest of t (guard.AppendTestMigrations), so the upgrade machinery has a
// version to upgrade to. The versions are package state that every guard
// call reads: t must not run in parallel, which t.Setenv enforces (it fails
// a parallel test and makes a later t.Parallel panic).
func WithMigrations(t *testing.T, ms ...guard.TestMigration) {
	t.Helper()
	t.Setenv(envTestMigrations, strconv.Itoa(len(ms)))
	t.Cleanup(guard.AppendTestMigrations(ms...))
}

// UpToVersion installs only the build's versions up to v until the
// returned restore runs (guard.KeepTestMigrationsUpTo), so a test installs
// a guard as an earlier release did and upgrades it after restore. Like
// WithMigrations, t must not run in parallel; restore also runs at cleanup.
func UpToVersion(t *testing.T, v int) (restore func()) {
	t.Helper()
	t.Setenv(envTestMigrations, "0")
	var once sync.Once
	r := guard.KeepTestMigrationsUpTo(v)
	restore = func() { once.Do(r) }
	t.Cleanup(restore)
	return restore
}

// NextVersion appends one test-only version after the build's own (see
// WithMigrations) and returns it. Its SQL creates the table
// basalt_meta.upgrade_probe_v<N> and is idempotent, so a test may delete
// its schema_version row and run init again.
func NextVersion(t *testing.T, nonBreaking bool) int {
	t.Helper()
	v := guard.LatestVersion() + 1
	WithMigrations(t, guard.TestMigration{
		Version:     v,
		SQL:         fmt.Sprintf("\nCREATE TABLE IF NOT EXISTS basalt_meta.upgrade_probe_v%d (id int PRIMARY KEY);\n", v),
		NonBreaking: nonBreaking,
	})
	return v
}

// Agent is a connected agent role.
type Agent struct {
	Role     string
	Password string
	URL      string
	Conn     *pgx.Conn
}

// NewAgent installs (or upgrades) the guard with an agent named name that
// can write the write tables and read the read tables, and connects as it.
func (d *DB) NewAgent(t *testing.T, name string, write, read []string) *Agent {
	t.Helper()
	pw := guard.NewPassword()
	d.Init(t, guard.AgentSpec{Name: name, Password: pw, Write: write, Read: read})
	role, err := d.Names.Agent(name)
	require.NoError(t, err)
	dsn, err := guard.AgentConnString(d.URL, role, pw)
	require.NoError(t, err)
	return &Agent{Role: role, Password: pw, URL: dsn, Conn: d.connect(t, dsn)}
}

// Connect opens another connection as the agent.
func (a *Agent) Connect(t *testing.T) *pgx.Conn {
	t.Helper()
	c, err := pgdial.Connect(context.Background(), a.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// Demo is a small app schema: leads, cascade targets the agent cannot
// write (lead_notes, note_tags by CASCADE; lead_owner by SET NULL on
// delete and update), an unrelated payroll table, and an app role.
const Demo = `
CREATE TABLE public.leads (
    id     bigint PRIMARY KEY,
    name   text NOT NULL,
    status text NOT NULL DEFAULT 'open',
    score  int  NOT NULL DEFAULT 0
);
CREATE TABLE public.lead_notes (
    id      bigint PRIMARY KEY,
    lead_id bigint NOT NULL REFERENCES public.leads ON DELETE CASCADE,
    note    text NOT NULL
);
CREATE TABLE public.note_tags (
    id      bigint PRIMARY KEY,
    note_id bigint NOT NULL REFERENCES public.lead_notes ON DELETE CASCADE,
    tag     text NOT NULL
);
CREATE TABLE public.lead_owner (
    id      bigint PRIMARY KEY,
    lead_id bigint REFERENCES public.leads ON DELETE SET NULL ON UPDATE SET NULL,
    owner   text
);
CREATE TABLE public.payroll (id bigint PRIMARY KEY, amount numeric);
INSERT INTO public.leads SELECT g, 'lead ' || g, 'open', g % 7 FROM generate_series(1, 200) g;
INSERT INTO public.lead_notes SELECT g, ((g - 1) / 2) + 1, 'note ' || g FROM generate_series(1, 60) g;
INSERT INTO public.note_tags SELECT g, g, 'tag ' || g FROM generate_series(1, 20) g;
INSERT INTO public.lead_owner SELECT g, 100 + g, 'owner ' || g FROM generate_series(1, 5) g;
`

// WithDemo loads Demo.
func (d *DB) WithDemo(t *testing.T) *DB {
	t.Helper()
	d.Exec(t, Demo)
	return d
}

// Timeout is the statement timeout tests run guarded transactions with
// (the engine's default).
const Timeout = 5 * time.Second

// Guarded runs stmts in one transaction as the engine does: BeginGuarded,
// then each statement followed by FinishChange, then COMMIT.
func Guarded(ctx context.Context, c *pgx.Conn, in guard.Intent, stmts ...string) error {
	return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in, Timeout); err != nil {
			return err
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
			if _, err := guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: s}); err != nil {
				return err
			}
		}
		return nil
	})
}

// SQLState returns the SQLSTATE of err, or "" when it has none.
func SQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
