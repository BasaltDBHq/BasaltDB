package setup_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// roleACL is every privilege role holds on a table, view, sequence,
// column or schema of the database, one "object privilege" line each.
func roleACL(t *testing.T, d *guardtest.DB, role string) []string {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `
WITH r AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)
SELECT c.oid::pg_catalog.regclass::text || ' ' || a.privilege_type
  FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a, r WHERE a.grantee = r.oid
UNION ALL
SELECT c.oid::pg_catalog.regclass::text || '.' || t.attname || ' ' || a.privilege_type
  FROM pg_catalog.pg_attribute t JOIN pg_catalog.pg_class c ON c.oid = t.attrelid, LATERAL pg_catalog.aclexplode(t.attacl) a, r WHERE a.grantee = r.oid
UNION ALL
SELECT 'schema ' || n.nspname || ' ' || a.privilege_type
  FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(n.nspacl) a, r WHERE a.grantee = r.oid
ORDER BY 1`, role)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// keepGrants makes p an AGENT code that names no tables.
func keepGrants(verifier bool) func(p *setupcode.Payload) {
	return func(p *setupcode.Payload) {
		p.Kind = setupcode.KindAgent
		p.Agent.Write, p.Agent.Read = []string{}, []string{}
		if !verifier {
			p.Agent.Verifier = ""
		}
	}
}

// installTwoOfFive installs the bot with 2 of the demo's 5 tables in
// public: it writes public.leads and reads public.lead_notes.
func installTwoOfFive(t *testing.T, d *guardtest.DB) []string {
	t.Helper()
	code := newCode(t, d, func(p *setupcode.Payload) { p.Agent.Read = []string{"public.lead_notes"} })
	_, give := personPasskey(t)
	_, err := setup.Run(context.Background(), d.Admin, request(code), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	acl := roleACL(t, d, d.Names.Prefix+"_agent_bot")
	require.Contains(t, acl, "lead_notes SELECT")
	require.Contains(t, acl, "leads UPDATE")
	require.NotContains(t, acl, "payroll SELECT")
	return acl
}

// The role holds 2 of the 5 tables in public. An AGENT code that names no
// tables runs, with or without a new password (a re-run after the database
// rejected the bot's password), and the role holds exactly those 2: no
// table, sequence, column or schema privilege is added or revoked, and it
// never falls back to every table in public.
func TestAgentCodeWithNoTablesKeepsTheRoleGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	before := installTwoOfFive(t, d)
	role := d.Names.Prefix + "_agent_bot"

	code := newCode(t, d, keepGrants(false))
	desc, err := setup.Describe(request(code))
	require.NoError(t, err)
	require.True(t, desc.KeepsGrants)
	require.Empty(t, desc.Write)
	require.Empty(t, desc.Read)
	require.Nil(t, desc.AllTablesSchemas)
	checked, err := setup.Check(ctx, d.Admin, connectPage(code))
	require.NoError(t, err)
	require.False(t, checked.RunsAsInstall)
	require.False(t, checked.Ticked)
	require.Empty(t, checked.Tables, "nothing is listed: the grants stay")
	require.Contains(t, checked.Summary, "bot keeps the tables it can use now: this setup grants and revokes none.")
	labeled := map[string]bool{}
	for _, c := range checked.Columns {
		labeled[c.Table] = true
	}
	require.Equal(t, map[string]bool{"public.lead_notes": true, "public.leads": true}, labeled, "the labels cover the tables the role holds")
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{ColumnClasses: []setup.ColumnClass{
		{Table: "public.payroll", Column: "id", Label: setup.Label{Class: "PUBLIC"}, Was: setup.Label{Class: "UNCLASSIFIED"}},
	}})
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err), "no label on a table the role does not hold")
	res, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.Equal(t, before, roleACL(t, d, role), "exactly the role's grants")

	// The database rejects the bot's password: the re-run's code rotates
	// it and names no tables. The grants stay exactly as they were.
	d.Exec(t, `ALTER ROLE `+pgx.Identifier{role}.Sanitize()+` PASSWORD 'not-the-bots'`)
	rotate := newCode(t, d, keepGrants(true))
	checked, err = setup.Check(ctx, d.Admin, connectPage(rotate))
	require.NoError(t, err)
	require.Contains(t, checked.Summary[0], "This replaces the password of the existing agent bot")
	require.False(t, checked.Ticked)
	res, err = setup.Run(ctx, d.Admin, ticked(rotate), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.Equal(t, before, roleACL(t, d, role), "nothing added, nothing revoked")
	var ok bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT has_table_privilege($1, 'public.payroll', 'SELECT')`, role).Scan(&ok))
	require.False(t, ok, "never every table in public")
}

// A role that is not an agent of this install is refused, as an AGENT code
// with tables refuses it: keeping its grants never adopts it.
func TestAgentCodeWithNoTablesRefusesANonAgentRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	installTwoOfFive(t, d)
	rogue := pgx.Identifier{d.Names.Prefix + "_agent_rogue"}.Sanitize()
	d.Exec(t, `CREATE ROLE `+rogue+` LOGIN; GRANT SELECT ON public.payroll TO `+rogue)
	before := roleACL(t, d, d.Names.Prefix+"_agent_rogue")

	code := newCode(t, d, func(p *setupcode.Payload) {
		keepGrants(false)(p)
		p.Agent.Name = "rogue"
	})
	_, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Error(t, err)
	require.Equal(t, before, roleACL(t, d, d.Names.Prefix+"_agent_rogue"), "nothing changed")
}

// The role was dropped: an AGENT code with a new password and no tables
// runs as an INSTALL, with ticks. Check lists the tables of public for the
// person to tick; a run without ticks is refused NO_TABLES, nothing
// changed, and a run with ticks grants exactly the ticked tables.
func TestAgentCodeWithNoTablesForADroppedRoleIsAnInstallWithTicks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	installTwoOfFive(t, d)
	role := pgx.Identifier{d.Names.Prefix + "_agent_bot"}.Sanitize()
	d.Exec(t, `DROP OWNED BY `+role+`; DROP ROLE `+role)

	code := newCode(t, d, keepGrants(true))
	checked, err := setup.Check(ctx, d.Admin, connectPage(code))
	require.NoError(t, err)
	require.True(t, checked.RunsAsInstall)
	require.True(t, checked.Ticked, "the person ticks the tables")
	require.Equal(t, []string{"public.lead_notes", "public.lead_owner", "public.leads", "public.note_tags", "public.payroll"}, checked.Tables)
	require.Contains(t, checked.Summary[0], "This creates the agent bot")

	// No ticks: refused, nothing changed, on the page and without it.
	_, err = setup.Run(ctx, d.Admin, connectPage(code), setup.RunInput{})
	require.Equal(t, setup.CodeNoTables, codeOf(t, err))
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Equal(t, setup.CodeNoTables, codeOf(t, err), "never every table in public unticked")
	require.False(t, roleExists(t, d, d.Names.Prefix+"_agent_bot"), "nothing changed")

	res, err := setup.Run(ctx, d.Admin, ticked(code, "public.leads"), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.True(t, hasPrivilege(t, d, "public.leads", "UPDATE"))
	require.False(t, hasPrivilege(t, d, "public.lead_notes", "SELECT"), "only the ticked table")
	require.False(t, hasPrivilege(t, d, "public.payroll", "SELECT"))
}

// The role exists but holds no table: an AGENT code that keeps its grants
// is treated like one for a dropped role. Check lists the tables of public
// with ticks; a run without ticks is NO_TABLES, nothing changed, and a run
// with ticks grants exactly the ticked tables. Never all of public.
func TestAgentCodeWithNoTablesForARoleWithNoGrantsNeedsTicks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	installTwoOfFive(t, d)
	role := d.Names.Prefix + "_agent_bot"
	ident := pgx.Identifier{role}.Sanitize()
	d.Exec(t, `REVOKE ALL ON ALL TABLES IN SCHEMA public FROM `+ident+`; REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM `+ident)
	require.Empty(t, grantedOn(roleACL(t, d, role)), "the role holds no table")

	for _, verifier := range []bool{false, true} {
		code := newCode(t, d, keepGrants(verifier))
		checked, err := setup.Check(ctx, d.Admin, connectPage(code))
		require.NoError(t, err)
		require.False(t, checked.RunsAsInstall, "the role exists")
		require.True(t, checked.Ticked, "the person ticks the tables")
		require.Equal(t, []string{"public.lead_notes", "public.lead_owner", "public.leads", "public.note_tags", "public.payroll"}, checked.Tables)

		_, err = setup.Run(ctx, d.Admin, connectPage(code), setup.RunInput{})
		require.Equal(t, setup.CodeNoTables, codeOf(t, err), "no ticks on the page")
		_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
		require.Equal(t, setup.CodeNoTables, codeOf(t, err), "never every table in public unticked")
		require.Empty(t, grantedOn(roleACL(t, d, role)), "nothing changed")
	}

	code := newCode(t, d, keepGrants(true))
	res, err := setup.Run(ctx, d.Admin, ticked(code, "public.note_tags"), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.True(t, hasPrivilege(t, d, "public.note_tags", "SELECT"))
	require.False(t, hasPrivilege(t, d, "public.leads", "SELECT"), "only the ticked table")
	require.False(t, hasPrivilege(t, d, "public.payroll", "SELECT"))
}

// grantedOn are the ACL lines on tables, views and sequences: no schema
// usage, which a role may keep with no table.
func grantedOn(acl []string) []string {
	var out []string
	for _, l := range acl {
		if !strings.HasPrefix(l, "schema ") {
			out = append(out, l)
		}
	}
	return out
}
