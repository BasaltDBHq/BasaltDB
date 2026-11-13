package guard_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// piiFixture is the app schema of the PII tests: customers, which bot may
// read in part (id, email, phone; not ssn), vault, which only other may
// read, a view over customers, and leads (guardtest.Demo).
const piiFixture = `
CREATE TABLE public.customers (id bigint PRIMARY KEY, email text, phone varchar(20), ssn text);
CREATE TABLE public.vault (id bigint PRIMARY KEY, secret text);
CREATE VIEW public.customer_emails AS SELECT id, email FROM public.customers;
`

// piiDB is a guard with two agents: bot reads leads, customer_emails and
// customers in part; other reads customers and vault whole.
type piiDB struct {
	*guardtest.DB
	bot, other *guardtest.Agent
}

func newPIIDB(t *testing.T) piiDB {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, piiFixture)
	bot := d.NewAgent(t, "bot", leads, []string{"public.leads", "public.customer_emails"})
	other := d.NewAgent(t, "other", nil, []string{"public.customers", "public.vault"})
	d.Exec(t, `GRANT SELECT (id, email, phone) ON public.customers TO `+bot.Role)
	return piiDB{DB: d, bot: bot, other: other}
}

// classifyAll writes a class for every readable column, as basalt classify
// does after the person accepted the suggestions.
func (p piiDB) classifyAll(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rows, err := p.Admin.Query(ctx, `SELECT table_schema, table_name, column_name, data_type
		FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guard.PIIColumn, error) {
		var c guard.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guard.ClassPublic
		return c, err
	})
	require.NoError(t, err)
	for i := range cols {
		switch cols[i].Table + "." + cols[i].Column {
		case "customers.email":
			cols[i].Class, cols[i].EntityType = guard.ClassIdentifier, guard.EntityEmail
		case "customers.phone":
			cols[i].Class, cols[i].EntityType, cols[i].PhoneRegion = guard.ClassIdentifier, guard.EntityPhone, "ID"
		case "customers.ssn", "vault.secret":
			cols[i].Class = guard.ClassSecret
		case "leads.name":
			cols[i].Class = guard.ClassUnclassified
			cols[i].SuggestedClass, cols[i].SuggestedEntityType = guard.ClassIdentifier, guard.EntityPersonName
			cols[i].Reason = "NAME:name"
		}
	}
	p.write(t, cols)
}

func (p piiDB) write(t *testing.T, cols []guard.PIIColumn) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, pgx.BeginFunc(ctx, p.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, p.Names, guard.Classification{Columns: cols, At: time.Now()})
	}))
}

func strings2(t *testing.T, q guard.Querier, sql string) []string {
	t.Helper()
	rows, err := q.Query(context.Background(), sql)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

func TestPIIAgentCannotTouchTheTables(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.classifyAll(t)
	ctx := context.Background()

	refused := func(sql string, codes ...string) {
		t.Helper()
		_, err := p.bot.Conn.Exec(ctx, sql)
		require.Contains(t, codes, guardtest.SQLState(err), "%s: %v", sql, err)
	}
	for _, sql := range []string{
		`SELECT 1 FROM basalt_meta.pii_columns`,
		`SELECT 1 FROM basalt_meta.pii_catalog`,
		`INSERT INTO basalt_meta.pii_columns (table_schema, table_name, column_name, data_type, class)
			VALUES ('public', 'leads', 'id', 'bigint', 'PUBLIC')`,
		`UPDATE basalt_meta.pii_columns SET class = 'PUBLIC'`,
		`DELETE FROM basalt_meta.pii_columns`,
		`INSERT INTO basalt_meta.pii_catalog (fingerprint, classified_at, classified_by)
			VALUES (sha256(''), now(), 'x')`,
		`UPDATE basalt_meta.pii_catalog SET classified_by = 'x'`,
		`DELETE FROM basalt_meta.pii_catalog`,
	} {
		refused(sql, "42501")
	}
	// A view refuses a write for want of the privilege or, for the join in
	// agent_pii_columns, because it cannot be updated at all.
	for _, sql := range []string{
		`INSERT INTO basalt_meta.agent_pii_columns (table_schema, table_name, column_name)
			VALUES ('public', 'leads', 'id')`,
		`UPDATE basalt_meta.agent_pii_columns SET class = 'PUBLIC'`,
		`DELETE FROM basalt_meta.agent_pii_columns`,
		`INSERT INTO basalt_meta.agent_pii_catalog (fingerprint) VALUES (sha256(''))`,
		`UPDATE basalt_meta.agent_pii_catalog SET fingerprint = sha256('')`,
		`DELETE FROM basalt_meta.agent_pii_catalog`,
	} {
		refused(sql, "42501", "55000")
	}

	// What the agent may use.
	require.Positive(t, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns`))
	require.Equal(t, 1, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_catalog`))
	require.Zero(t, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.pii_unclassified() WHERE why = 'NEW'`))
	require.Equal(t, 1, count(t, p.bot.Conn, `SELECT count(1)::int FROM (SELECT 1 FROM basalt_meta.pii_readable_columns() LIMIT 1) q`))
	var fp []byte
	require.NoError(t, p.bot.Conn.QueryRow(ctx, `SELECT basalt_meta.pii_fingerprint()`).Scan(&fp))
	require.Len(t, fp, sha256.Size)

	// Nothing else: EXECUTE on the functions is not granted to PUBLIC.
	for _, fn := range []string{"pii_unclassified()", "pii_fingerprint()", "pii_readable_columns()"} {
		var public bool
		require.NoError(t, p.Admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_proc p, aclexplode(p.proacl) a
			WHERE p.oid = ('basalt_meta.' || $1)::regprocedure AND a.grantee = 0)`, fn).Scan(&public))
		require.False(t, public, fn)
	}
}

func TestAgentPIIColumnsShowsOnlyReadableColumns(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.classifyAll(t)

	got := strings2(t, p.bot.Conn, `SELECT l FROM (SELECT table_name || '.' || column_name || ':' || class AS l
		FROM basalt_meta.agent_pii_columns) q ORDER BY l COLLATE "C"`)
	require.Equal(t, []string{
		"customer_emails.email:PUBLIC", "customer_emails.id:PUBLIC",
		"customers.email:IDENTIFIER", "customers.id:PUBLIC", "customers.phone:IDENTIFIER",
		"leads.id:PUBLIC", "leads.name:UNCLASSIFIED", "leads.score:PUBLIC", "leads.status:PUBLIC",
	}, got)
	// other sees the columns bot cannot: ssn and vault.
	require.Equal(t, 1, count(t, p.other.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns
		WHERE table_name = 'customers' AND column_name = 'ssn' AND class = 'SECRET'`))
	require.Equal(t, 1, count(t, p.other.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns
		WHERE table_name = 'vault' AND column_name = 'secret'`))

	// table_oid and attnum resolve to the column, as pgx reports it.
	var oid uint32
	var attnum int16
	var entity, region string
	require.NoError(t, p.bot.Conn.QueryRow(context.Background(), `SELECT table_oid, attnum, entity_type, phone_region
		FROM basalt_meta.agent_pii_columns WHERE table_name = 'customers' AND column_name = 'phone'`).
		Scan(&oid, &attnum, &entity, &region))
	require.Equal(t, guard.EntityPhone, entity)
	require.Equal(t, "ID", region)
	require.Equal(t, 1, count(t, p.Admin, `SELECT count(1)::int FROM pg_attribute
		WHERE attrelid = $1 AND attnum = $2 AND attname = 'phone' AND attrelid = 'public.customers'::regclass`, oid, attnum))
}

// leakNotices runs query on a new connection to dsn after creating the
// leaky pg_temp.leak, and returns the notices it raised and the rows.
func leakNotices(t *testing.T, dsn, query string) ([]string, int) {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgdial.ConnConfig(dsn)
	require.NoError(t, err)
	var mu sync.Mutex
	var notices []string
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		mu.Lock()
		defer mu.Unlock()
		notices = append(notices, n.Message)
	}
	c, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer c.Close(ctx)
	_, err = c.Exec(ctx, `CREATE FUNCTION pg_temp.leak(a text, b text, c text) RETURNS boolean
		LANGUAGE plpgsql COST 0.0000001 AS $$
		BEGIN
			RAISE NOTICE 'leak %.%:%', a, b, c;
			RETURN true;
		END $$`)
	require.NoError(t, err)
	n := count(t, c, `SELECT count(1)::int FROM (`+query+`) q`)
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), notices...), n
}

func TestAgentPIIColumnsLeakyFunction(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.classifyAll(t)

	notices, rows := leakNotices(t, p.bot.URL,
		`SELECT 1 FROM basalt_meta.agent_pii_columns WHERE pg_temp.leak(table_name, column_name, class)`)
	require.Equal(t, 9, rows)
	require.Len(t, notices, rows)
	joined := strings.Join(notices, "\n")
	// A column of a table bot has no grant on, and one left out of a
	// column-level grant on a table it reads in part.
	require.NotContains(t, joined, "vault")
	require.NotContains(t, joined, "ssn")
	require.NotContains(t, joined, "SECRET")
	require.NotContains(t, joined, "payroll")
	require.Contains(t, joined, "leak customers.email:IDENTIFIER")
}

func TestAgentPIICatalogLeakyFunction(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	const query = `SELECT 1 FROM basalt_meta.agent_pii_catalog
		WHERE pg_temp.leak(encode(fingerprint, 'hex'), classified_at::text, '')`

	// Before the first basalt classify: no row.
	notices, rows := leakNotices(t, p.bot.URL, query)
	require.Zero(t, rows)
	require.Empty(t, notices)

	p.classifyAll(t)
	notices, rows = leakNotices(t, p.bot.URL, query)
	require.Equal(t, 1, rows)
	require.Len(t, notices, 1)

	// A login role outside the agents group, granted SELECT on the view
	// for the test, reaches the filter and fails it before leak runs.
	outsider := p.Names.Prefix + "_outsider"
	p.Exec(t, `CREATE ROLE `+outsider+` LOGIN PASSWORD 'outsider'`)
	p.Exec(t, `GRANT USAGE ON SCHEMA basalt_meta TO `+outsider)
	p.Exec(t, `GRANT SELECT ON basalt_meta.agent_pii_catalog TO `+outsider)
	dsn, err := guard.AgentConnString(p.URL, outsider, "outsider")
	require.NoError(t, err)
	notices, rows = leakNotices(t, dsn, query)
	require.Zero(t, rows)
	require.Empty(t, notices)
}

func TestPIIUnclassified(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	const query = `SELECT table_name || '.' || column_name || ':' || data_type || ':' || why
		FROM basalt_meta.pii_unclassified()`

	// Nothing classified yet: every column bot can read is NEW, in order.
	require.Equal(t, []string{
		"public.customer_emails.email", "public.customer_emails.id",
		"public.customers.email", "public.customers.id", "public.customers.phone",
		"public.leads.id", "public.leads.name", "public.leads.score", "public.leads.status",
	}, strings2(t, p.bot.Conn, `SELECT table_schema || '.' || table_name || '.' || column_name
		FROM basalt_meta.pii_unclassified() WHERE why = 'NEW'`))

	p.classifyAll(t)
	require.Equal(t, []string{"leads.name:text:UNCLASSIFIED"}, strings2(t, p.bot.Conn, query))

	// A rename is a new column; a type change keeps the class but asks for
	// review; a length change is not a type change.
	p.Exec(t, `ALTER TABLE public.customers RENAME COLUMN email TO email_address`)
	p.Exec(t, `ALTER TABLE public.leads ALTER COLUMN score TYPE bigint`)
	p.Exec(t, `ALTER TABLE public.customers ALTER COLUMN phone TYPE varchar(40)`)
	p.Exec(t, `GRANT SELECT (email_address) ON public.customers TO `+p.bot.Role)
	require.Equal(t, []string{
		"customers.email_address:text:NEW",
		"leads.name:text:UNCLASSIFIED",
		"leads.score:bigint:TYPE_CHANGED",
	}, strings2(t, p.bot.Conn, query))
	// The renamed column's old row shows in no view.
	require.Zero(t, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns
		WHERE table_name = 'customers' AND column_name IN ('email', 'email_address')`))

	// other reads customers and vault, not leads: only its own columns.
	require.Equal(t, []string{"customers.email_address:text:NEW"}, strings2(t, p.other.Conn, query))
}

func TestPIIReadableColumnsAndFingerprint(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	ctx := context.Background()

	lines := strings2(t, p.Admin, `SELECT l FROM (SELECT table_schema || '.' || table_name || '.' || column_name || ':' || data_type AS l
		FROM basalt_meta.pii_readable_columns()) q ORDER BY l COLLATE "C"`)
	require.Equal(t, []string{
		"public.customer_emails.email:text", "public.customer_emails.id:bigint",
		"public.customers.email:text", "public.customers.id:bigint", "public.customers.phone:character varying",
		"public.customers.ssn:text",
		"public.leads.id:bigint", "public.leads.name:text", "public.leads.score:integer", "public.leads.status:text",
		"public.vault.id:bigint", "public.vault.secret:text",
	}, lines)

	want := fingerprintOf(t, p.Admin)
	var got []byte
	require.NoError(t, p.bot.Conn.QueryRow(ctx, `SELECT basalt_meta.pii_fingerprint()`).Scan(&got))
	require.Equal(t, want, got)

	// A length change keeps it; a new readable column moves it.
	p.Exec(t, `ALTER TABLE public.customers ALTER COLUMN phone TYPE varchar(40)`)
	require.NoError(t, p.bot.Conn.QueryRow(ctx, `SELECT basalt_meta.pii_fingerprint()`).Scan(&got))
	require.Equal(t, want, got)
	p.Exec(t, `ALTER TABLE public.vault ADD COLUMN note text`)
	require.NoError(t, p.bot.Conn.QueryRow(ctx, `SELECT basalt_meta.pii_fingerprint()`).Scan(&got))
	require.NotEqual(t, want, got)
}

func TestWriteClassificationRunsAsGuard(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	ctx := context.Background()
	p.classifyAll(t)

	var admin string
	require.NoError(t, p.Admin.QueryRow(ctx, `SELECT session_user::text`).Scan(&admin))
	require.Equal(t, 0, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_columns
		WHERE (class = 'UNCLASSIFIED') <> (confirmed_by IS NULL)
		   OR (class <> 'UNCLASSIFIED' AND confirmed_by <> $1)`, admin))
	require.Equal(t, 1, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_catalog
		WHERE fingerprint = basalt_meta.pii_fingerprint() AND classified_by = $1`, admin))

	// The write runs under the guard role and puts the caller's role and
	// search_path back after, SET LOCAL ones included.
	settings := func(tx pgx.Tx) (string, string) {
		var role, path string
		require.NoError(t, tx.QueryRow(ctx, `SELECT current_user::text, current_setting('search_path')`).Scan(&role, &path))
		return role, path
	}
	require.NoError(t, pgx.BeginFunc(ctx, p.Admin, func(tx pgx.Tx) error {
		before := [2]string{}
		before[0], before[1] = settings(tx)
		require.NoError(t, guard.WriteClassification(ctx, tx, p.Names, guard.Classification{At: time.Now()}))
		after := [2]string{}
		after[0], after[1] = settings(tx)
		require.Equal(t, before, after)
		require.Equal(t, admin, after[0])
		return nil
	}))
	require.NoError(t, pgx.BeginFunc(ctx, p.Admin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SET LOCAL search_path = public, pg_temp; SET LOCAL ROLE `+p.Names.Guard())
		require.NoError(t, err)
		require.NoError(t, guard.WriteClassification(ctx, tx, p.Names, guard.Classification{At: time.Now()}))
		role, path := settings(tx)
		require.Equal(t, p.Names.Guard(), role)
		require.Equal(t, "public, pg_temp", path)
		return nil
	}))

	// Rows of columns that are gone are deleted. A confirmed class survives
	// a revoked grant (owner decision OR-1): customers.ssn keeps SECRET
	// although no agent can read it now.
	p.Exec(t, `ALTER TABLE public.vault DROP COLUMN secret`)
	p.Exec(t, `REVOKE SELECT ON public.customers FROM `+p.other.Role)
	p.write(t, nil)
	require.Zero(t, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_columns
		WHERE table_name = 'vault' AND column_name = 'secret'`))
	require.Equal(t, 1, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_columns
		WHERE table_name = 'customers' AND column_name = 'ssn' AND class = 'SECRET'`))
	require.Equal(t, 1, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_columns
		WHERE table_name = 'customers' AND column_name = 'email'`))
	// Granted again, the column comes back with its class, not as NEW.
	p.Exec(t, `GRANT SELECT ON public.customers TO `+p.other.Role)
	other := p.other.Connect(t)
	cols, err := guard.PIIUnclassified(ctx, other)
	require.NoError(t, err)
	for _, c := range cols {
		require.NotEqual(t, "public.customers.ssn", c.Name())
	}

	// The table checks hold: an IDENTIFIER needs an entity type.
	err = pgx.BeginFunc(ctx, p.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, p.Names, guard.Classification{At: time.Now(), Columns: []guard.PIIColumn{
			{Schema: "public", Table: "leads", Column: "name", DataType: "text", Class: guard.ClassIdentifier},
		}})
	})
	require.Equal(t, "23514", guardtest.SQLState(err), "%v", err)
}

func TestPIIMigrationIsIdempotentAndRemovable(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.classifyAll(t)
	ctx := context.Background()

	// Running version 15 again keeps the rows.
	p.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version >= 15`)
	p.Init(t, guard.AgentSpec{Name: "bot", Password: p.bot.Password, Write: leads, Read: leads})
	require.Equal(t, 1, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_catalog`))
	require.Positive(t, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns`))

	p.Exec(t, `DROP SCHEMA basalt_meta CASCADE`)
	var left int
	require.NoError(t, p.Admin.QueryRow(ctx, `SELECT (SELECT count(1) FROM pg_class WHERE relname LIKE '%pii%')
		+ (SELECT count(1) FROM pg_proc WHERE proname LIKE 'pii%')`).Scan(&left))
	require.Zero(t, left)
}

// loginRole creates a NOINHERIT login role: a member of what it is granted
// that holds none of its privileges until SET ROLE.
func (p piiDB) loginRole(t *testing.T, name string) (string, string) {
	t.Helper()
	role := p.Names.Prefix + "_" + name
	p.Exec(t, `CREATE ROLE `+role+` LOGIN NOINHERIT PASSWORD 'pw'`)
	dsn, err := guard.AgentConnString(p.URL, role, "pw")
	require.NoError(t, err)
	return role, dsn
}

func TestPIIViewsAreSecurityBarriers(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	// agent_pii_catalog's filter has no column of the view in it, so
	// Postgres runs it as a one-time filter before any qual of the caller's
	// query and the leaky-function test cannot fail without the barrier.
	// Check the option itself on both views.
	require.Equal(t, []string{"agent_pii_catalog", "agent_pii_columns"}, strings2(t, p.Admin, `SELECT c.relname::text
		FROM pg_class c WHERE c.relnamespace = 'basalt_meta'::regnamespace AND c.relname LIKE 'agent_pii%'
		  AND 'security_barrier=true' = ANY (c.reloptions) ORDER BY 1`))
}

func TestPIIViewsFilterOnTheLoginRole(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.classifyAll(t)
	ctx := context.Background()

	// A login role that can SET ROLE to bot: as bot, current_user is bot,
	// which may read the views, but session_user is still the login role,
	// which may select no column and is not an agent.
	role, dsn := p.loginRole(t, "person")
	p.Exec(t, `GRANT `+p.bot.Role+` TO `+role)
	c, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer c.Close(ctx)
	_, err = c.Exec(ctx, `SET ROLE `+p.bot.Role)
	require.NoError(t, err)
	require.Equal(t, 9, count(t, p.bot.Conn, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns`))
	require.Zero(t, count(t, c, `SELECT count(1)::int FROM basalt_meta.agent_pii_columns`))
	require.Zero(t, count(t, c, `SELECT count(1)::int FROM basalt_meta.agent_pii_catalog`))
	require.Empty(t, strings2(t, c, `SELECT column_name FROM basalt_meta.pii_unclassified()`))
}

func TestPIIReadableColumnsNeedAnInheritingMember(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)

	// A member of the agents group that does not inherit it (as the admin
	// who created the roles is from Postgres 16) is not an agent: what it
	// may select is not a readable column.
	role, _ := p.loginRole(t, "admin2")
	p.Exec(t, `GRANT `+p.Names.Agents()+` TO `+role)
	p.Exec(t, `GRANT SELECT ON public.payroll TO `+role)
	require.Zero(t, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_readable_columns()
		WHERE table_name = 'payroll'`))

	// An inheriting member makes it readable.
	p.Exec(t, `GRANT SELECT ON public.payroll TO `+p.other.Role)
	require.Equal(t, 2, count(t, p.Admin, `SELECT count(1)::int FROM basalt_meta.pii_readable_columns()
		WHERE table_name = 'payroll'`))
}

// A column in a schema the role has no USAGE on cannot be read, so it is
// neither a readable column nor unclassified (EV-14). Granting USAGE to the
// agent makes it both; USAGE granted to another agent, or SELECT through a
// column grant, changes nothing for a role without it.
func TestPIIColumnsNeedSchemaUsage(t *testing.T) {
	t.Parallel()
	p := newPIIDB(t)
	p.Exec(t, `CREATE SCHEMA hidden; CREATE TABLE hidden.t (a text)`)
	p.Exec(t, `GRANT SELECT ON hidden.t TO `+p.bot.Role)
	hidden := `SELECT count(1)::int FROM basalt_meta.pii_readable_columns() WHERE table_schema = 'hidden'`
	unclassified := `SELECT count(1)::int FROM basalt_meta.pii_unclassified() WHERE table_schema = 'hidden'`

	require.Zero(t, count(t, p.Admin, hidden), "no agent has USAGE on hidden")
	require.Zero(t, count(t, p.bot.Conn, unclassified))

	p.Exec(t, `GRANT USAGE ON SCHEMA hidden TO `+p.other.Role)
	require.Zero(t, count(t, p.Admin, hidden), "other has USAGE but no SELECT; bot SELECT but no USAGE")
	require.Zero(t, count(t, p.bot.Conn, unclassified))

	p.Exec(t, `GRANT USAGE ON SCHEMA hidden TO `+p.bot.Role)
	require.Equal(t, 1, count(t, p.Admin, hidden))
	require.Equal(t, 1, count(t, p.bot.Conn, unclassified))
	require.Zero(t, count(t, p.other.Conn, unclassified), "other may not select the column")
}
