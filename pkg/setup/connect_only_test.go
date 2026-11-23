package setup_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// connectOnly makes p a connect-only code that asks for every table in
// public: no target, an engine key, agent.allTables.
func connectOnly(t *testing.T) func(p *setupcode.Payload) {
	t.Helper()
	key, _, _ := engineKey(t)
	return func(p *setupcode.Payload) {
		p.Target, p.Engine = nil, key
		p.Agent.Write, p.Agent.Read = nil, nil
		p.Agent.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	}
}

func connectPage(code string) setup.Request {
	return setup.Request{Code: code, Now: time.Now(), ConnectPage: true}
}

// The laptop path refuses a connect-only code first, before the clock;
// the connect page describes it with no target and the schema it asks for.
func TestConnectOnlyRefusedOnTheLaptop(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	code := newCode(t, d, connectOnly(t))

	_, err := setup.Describe(request(code))
	require.Equal(t, setup.CodeConnectOnly, codeOf(t, err))
	require.Contains(t, err.Error(), "This setup code is for the connect page: open the link bot sent")
	_, err = setup.Describe(setup.Request{Code: code, Now: time.Now().Add(48 * time.Hour)})
	require.Equal(t, setup.CodeConnectOnly, codeOf(t, err), "before the clock checks")
	_, err = setup.Check(context.Background(), d.Admin, request(code))
	require.Equal(t, setup.CodeConnectOnly, codeOf(t, err))
	_, err = setup.Run(context.Background(), d.Admin, request(code), setup.RunInput{})
	require.Equal(t, setup.CodeConnectOnly, codeOf(t, err))

	desc, err := setup.Describe(connectPage(code))
	require.NoError(t, err)
	require.Nil(t, desc.Target)
	require.Equal(t, []string{"public"}, desc.AllTablesSchemas)
	require.Empty(t, desc.Write)
	require.Contains(t, desc.Summary, "bot will be able to read and change rows in every table in schema public that the admin role owns when the setup runs, "+
		"up to 10 rows at a time without asking you, 11 to 50 with your passkey, never more. It cannot change your tables' structure.")
}

// A connect-only code with agent.allTables runs in the database the
// connection names: Check lists the tables the admin role owns and those
// it leaves out, and Run grants exactly the listed ones.
func TestConnectOnlyAllTablesInstalls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	other := d.Names.Prefix + "_app_owner"
	d.Exec(t, `CREATE ROLE `+pgx.Identifier{other}.Sanitize()+` NOLOGIN;
		CREATE TABLE public.audit (id bigint PRIMARY KEY);
		ALTER TABLE public.audit OWNER TO `+pgx.Identifier{other}.Sanitize()+`;
		CREATE TABLE public.events (id bigint, at date) PARTITION BY RANGE (at);
		CREATE TABLE public.events_2026 PARTITION OF public.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
		CREATE TABLE public."Mixed" (id bigint);
		CREATE SCHEMA crm_app; CREATE TABLE crm_app.accounts (id bigint PRIMARY KEY)`)
	code := newCode(t, d, connectOnly(t))

	checked, err := setup.Check(ctx, d.Admin, connectPage(code))
	require.NoError(t, err)
	require.Equal(t, setup.ConnDatabase(d.Admin.Config()), checked.Database)
	want := []string{"public.lead_notes", "public.lead_owner", "public.leads", "public.note_tags", "public.payroll"}
	require.Equal(t, append([]string{"public.events"}, want...), checked.Tables,
		"owned ordinary and partitioned tables of public; no partition, no quoted name, no other schema")
	require.Equal(t, []string{"public.events"}, checked.ReadOnly, "no primary key: read only")
	require.Equal(t, []setup.ExcludedTable{{Table: "public.audit", Owner: other}}, checked.Excluded)
	require.Contains(t, checked.Summary, "public.audit is not included: owned by "+other+".")
	require.Contains(t, checked.Summary, "public.events has no primary key, so bot can read it but not change its rows.")
	require.Contains(t, checked.Summary[0], "This creates the agent bot")
	require.False(t, checked.RunsAsInstall)

	_, give := personPasskey(t)
	res, err := setup.Run(ctx, d.Admin, ticked(code, checked.Tables...), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	require.True(t, res.Ran)
	role := d.Names.Prefix + "_agent_bot"
	for _, table := range want {
		var ok bool
		require.NoError(t, d.Admin.QueryRow(ctx, `SELECT has_table_privilege($1, $2, 'UPDATE')`, role, table).Scan(&ok))
		require.True(t, ok, table)
	}
	var granted, reads, writes bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT has_table_privilege($1, 'public.audit', 'SELECT'),
		has_table_privilege($1, 'public.events', 'SELECT'), has_table_privilege($1, 'public.events', 'UPDATE')`, role).Scan(&granted, &reads, &writes))
	require.False(t, granted, "a table another role owns is left out")
	require.True(t, reads)
	require.False(t, writes, "a table without a primary key is read only")
}

// The tables of an allTables code are read again in the setup's own
// transaction. Without ticks (the laptop command), a table made after the
// check the person approved stops the setup; with ticks, a ticked table
// dropped meanwhile does, and one made meanwhile is not included. Either
// way TABLES_CHANGED, nothing changed.
func TestAllTablesReadAgainInTheTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d := guardtest.New(t).WithDemo(t)
	code := newCode(t, d, func(p *setupcode.Payload) {
		p.Agent.Write, p.Agent.Read = nil, nil
		p.Agent.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	})
	_, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{
		Passkey: verified(t, give),
		Approve: func(setup.Plan) error {
			d.Exec(t, `CREATE TABLE public.made_meanwhile (id bigint PRIMARY KEY)`)
			return nil
		},
	})
	require.Equal(t, setup.CodeTablesChanged, codeOf(t, err))
	require.Zero(t, installedVersion(t, d), "nothing changed")
	require.False(t, roleExists(t, d, d.Names.Prefix+"_agent_bot"))

	d = guardtest.New(t).WithDemo(t)
	code = newCode(t, d, connectOnly(t))
	_, err = setup.Run(ctx, d.Admin, ticked(code, "public.leads", "public.payroll"), setup.RunInput{
		Passkey: verified(t, give),
		Approve: func(setup.Plan) error {
			d.Exec(t, `DROP TABLE public.payroll`)
			return nil
		},
	})
	require.Equal(t, setup.CodeTablesChanged, codeOf(t, err))
	require.Zero(t, installedVersion(t, d), "nothing changed")

	d = guardtest.New(t).WithDemo(t)
	code = newCode(t, d, connectOnly(t))
	_, err = setup.Run(ctx, d.Admin, ticked(code, "public.leads"), setup.RunInput{
		Passkey: verified(t, give),
		Approve: func(setup.Plan) error {
			d.Exec(t, `CREATE TABLE public.made_meanwhile (id bigint PRIMARY KEY)`)
			return nil
		},
	})
	require.NoError(t, err, "a table made since is simply not included")
	require.False(t, hasPrivilege(t, d, "public.made_meanwhile", "SELECT"))
}

func ticked(code string, tables ...string) setup.Request {
	r := connectPage(code)
	r.Included = &setup.Included{Tables: tables}
	return r
}

func hasPrivilege(t *testing.T, d *guardtest.DB, table, privilege string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT has_table_privilege($1, $2, $3)`,
		d.Names.Prefix+"_agent_bot", table, privilege).Scan(&ok))
	return ok
}

// The connect page's ticks: exactly the ticked tables are granted (read
// only without a primary key) and asked about; the entries' rules.
func TestTickedTables(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.events (id bigint, at date)`)
	code := newCode(t, d, connectOnly(t))

	for name, c := range map[string]struct {
		tables []string
		code   string
	}{
		"none":                {[]string{}, setup.CodeNoTables},
		"another schema":      {[]string{"crm.leads"}, setup.CodeAnswersInvalid},
		"a quoted name":       {[]string{`public."Leads"`}, setup.CodeAnswersInvalid},
		"upper case":          {[]string{"public.Leads"}, setup.CodeAnswersInvalid},
		"twice":               {[]string{"public.leads", "public.leads"}, setup.CodeAnswersInvalid},
		"a table never there": {[]string{"public.nowhere"}, setup.CodeTablesChanged},
	} {
		_, err := setup.Check(ctx, d.Admin, ticked(code, c.tables...))
		require.Equal(t, c.code, codeOf(t, err), name)
	}
	_, err := setup.Run(ctx, d.Admin, connectPage(code), setup.RunInput{})
	require.Equal(t, setup.CodeNoTables, codeOf(t, err), "the page always sends its ticks")

	checked, err := setup.Check(ctx, d.Admin, ticked(code, "public.leads", "public.events"))
	require.NoError(t, err)
	require.Equal(t, []string{"public.events", "public.leads"}, checked.Tables)
	require.Equal(t, []string{"public.events"}, checked.ReadOnly)
	for _, c := range checked.Columns {
		require.Contains(t, []string{"public.events", "public.leads"}, c.Table, "columns of the ticked tables only")
	}
	_, give := personPasskey(t)
	_, err = setup.Run(ctx, d.Admin, ticked(code, "public.leads", "public.events"), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	require.True(t, hasPrivilege(t, d, "public.leads", "UPDATE"))
	require.True(t, hasPrivilege(t, d, "public.events", "SELECT"))
	require.False(t, hasPrivilege(t, d, "public.events", "UPDATE"), "no primary key: read only")
	require.False(t, hasPrivilege(t, d, "public.payroll", "SELECT"), "an unticked table is not granted")
	_, err = setup.Check(ctx, d.Admin, ticked(code))
	require.Equal(t, "USED", codeOf(t, err), "a setup that ran is USED, whatever the ticks")

	// A code that names its tables ticks none.
	d2 := guardtest.New(t).WithDemo(t)
	named := newCode(t, d2, nil)
	_, err = setup.Check(ctx, d2.Admin, setup.Request{Code: named, Now: time.Now(), Included: &setup.Included{Tables: []string{"public.leads"}}})
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err))
	_, err = setup.Check(ctx, d2.Admin, setup.Request{Code: named, Now: time.Now(), Included: &setup.Included{}})
	require.NoError(t, err)
}

// No table the admin role owns in the schema: NO_TABLES, nothing changed.
func TestAllTablesNoTables(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t)
	code := newCode(t, d, connectOnly(t))
	_, err := setup.Check(ctx, d.Admin, connectPage(code))
	require.Equal(t, setup.CodeNoTables, codeOf(t, err))
	_, err = setup.Run(ctx, d.Admin, connectPage(code), setup.RunInput{})
	require.Equal(t, setup.CodeNoTables, codeOf(t, err))
	require.Zero(t, installedVersion(t, d), "nothing changed")
}

// A connect-only recovery code (AGENT with a verifier) creates the role as
// an INSTALL does when it does not exist, with the person's ticks, and
// rotates its password with the laptop's warning when it does.
func TestConnectOnlyRecoveryCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	recovery := func(p *setupcode.Payload) {
		connectOnly(t)(p)
		p.Kind = setupcode.KindAgent
	}
	_, give := personPasskey(t)

	first := newCode(t, d, recovery)
	checked, err := setup.Check(ctx, d.Admin, connectPage(first))
	require.NoError(t, err)
	require.True(t, checked.RunsAsInstall)
	require.True(t, checked.Ticked, "it runs as an INSTALL: the person ticks the tables")
	require.Contains(t, checked.Summary[0], "This creates the agent bot")
	_, err = setup.Run(ctx, d.Admin, connectPage(first), setup.RunInput{Passkey: verified(t, give)})
	require.Equal(t, setup.CodeNoTables, codeOf(t, err), "no ticks: never every table in public")
	_, err = setup.Run(ctx, d.Admin, ticked(first, "public.leads"), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	require.False(t, hasPrivilege(t, d, "public.payroll", "SELECT"), "only the ticked table")
	var exists bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, d.Names.Prefix+"_agent_bot").Scan(&exists))
	require.True(t, exists)

	second := newCode(t, d, recovery)
	checked, err = setup.Check(ctx, d.Admin, connectPage(second))
	require.NoError(t, err)
	require.False(t, checked.RunsAsInstall)
	require.False(t, checked.Ticked)
	require.Contains(t, checked.Summary[0], "This replaces the password of the existing agent bot")
	require.Contains(t, checked.Summary[0], "Run it only if bot itself gave you this code.")
	res, err := setup.Run(ctx, d.Admin, connectPage(second), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
}
