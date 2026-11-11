package guard_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func TestNamesValidate(t *testing.T) {
	t.Parallel()
	n := guard.Names{Prefix: guard.DefaultPrefix}
	require.NoError(t, n.Validate())
	require.Equal(t, "basalt_guard", n.Guard())
	require.Equal(t, "basalt_agents", n.Agents())
	role, err := n.Agent("bot")
	require.NoError(t, err)
	require.Equal(t, "basalt_agent_bot", role)

	for _, bad := range []string{"Bad", "a-b", "1a", "", "x;drop", strings.Repeat("a", 60)} {
		_, err := n.Agent(bad)
		require.ErrorIs(t, err, guard.ErrInvalidName, bad)
	}
	require.ErrorIs(t, guard.Names{Prefix: "Basalt"}.Validate(), guard.ErrInvalidName)
	require.ErrorIs(t, guard.Names{Prefix: strings.Repeat("p", 21)}.Validate(), guard.ErrInvalidName)
}

func TestAgentConnString(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ admin, want string }{
		"direct": {
			"postgres://postgres:secret@db.abcd.supabase.co:5432/postgres?sslmode=require",
			"postgres://basalt_agent_bot:pw@db.abcd.supabase.co:5432/postgres?sslmode=require",
		},
		"supabase pooler keeps the project ref": {
			"postgresql://postgres.abcd:secret@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
			"postgresql://basalt_agent_bot.abcd:pw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
		},
		"a dot elsewhere is part of the role": {
			"postgres://ops.admin:secret@127.0.0.1:5432/app",
			"postgres://basalt_agent_bot:pw@127.0.0.1:5432/app",
		},
		"no user": {"postgres://127.0.0.1/app", "postgres://basalt_agent_bot:pw@127.0.0.1/app"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := guard.AgentConnString(c.admin, "basalt_agent_bot", "pw")
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
	_, err := guard.AgentConnString("host=db user=postgres", "basalt_agent_bot", "pw")
	require.Error(t, err)
}

func TestPlanInitRedactsPassword(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	pw := guard.NewPassword()
	s, err := guard.PlanInit(context.Background(), d.Admin, guard.InitOptions{
		Names: d.Names, Agent: guard.AgentSpec{Name: "bot", Password: pw, Write: []string{"public.leads"}},
	})
	require.NoError(t, err)
	shown := s.SQL()
	require.NotContains(t, shown, pw)
	require.Contains(t, shown, "PASSWORD '********'")
	require.Contains(t, shown, "CREATE TABLE basalt_meta.ledger")
	require.Contains(t, shown, `GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."leads"`)

	_, err = guard.PlanInit(context.Background(), d.Admin, guard.InitOptions{
		Names: d.Names, Agent: guard.AgentSpec{Name: "bot", Password: "x'; DROP", Write: []string{"public.leads"}},
	})
	require.ErrorIs(t, err, guard.ErrInvalidAgent)
	_, err = guard.PlanInit(context.Background(), d.Admin, guard.InitOptions{
		Names: d.Names, Agent: guard.AgentSpec{Name: "bot", Password: pw, Write: []string{"public.nope"}},
	})
	require.ErrorContains(t, err, "nope")
}

func TestInstallCreatesSchemaAndRoles(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()

	v, err := guard.InstalledVersion(ctx, d.Admin)
	require.NoError(t, err)
	require.Equal(t, guard.LatestVersion(), v)

	var owner string
	require.NoError(t, d.Admin.QueryRow(ctx,
		`SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'basalt_meta'`).Scan(&owner))
	require.Equal(t, d.Names.Guard(), owner)

	var member bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT pg_has_role($1, $2, 'MEMBER')`, a.Role, d.Names.Agents()).Scan(&member))
	require.True(t, member)

	var timeout string
	require.NoError(t, a.Conn.QueryRow(ctx, `SHOW statement_timeout`).Scan(&timeout))
	require.Equal(t, "30s", timeout)

	// No default privileges name an agent role.
	var acl int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_default_acl
		WHERE array_to_string(defaclacl, ',') LIKE '%' || $1 || '%'`, d.Names.Agents()).Scan(&acl))
	require.Zero(t, acl)

	guarded := map[string]string{}
	rows, err := d.Admin.Query(ctx, `SELECT table_oid::text, reason FROM basalt_meta.guarded_tables`)
	require.NoError(t, err)
	for rows.Next() {
		var tbl, reason string
		require.NoError(t, rows.Scan(&tbl, &reason))
		guarded[tbl] = reason
	}
	require.NoError(t, rows.Err())
	require.Equal(t, map[string]string{
		"leads": "AGENT_WRITABLE", "lead_notes": "CASCADE_TARGET",
		"note_tags": "CASCADE_TARGET", "lead_owner": "CASCADE_TARGET",
	}, guarded)

	uncovered, err := guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Empty(t, uncovered)
}

func TestInstallIdempotent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	other := d.NewAgent(t, "bot", []string{"public.leads"}, nil) // rotates the password
	d.Init(t, guard.AgentSpec{})
	ctx := context.Background()

	var versions, triggers int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM basalt_meta.schema_version`).Scan(&versions))
	require.Equal(t, guard.LatestVersion(), versions)
	require.NoError(t, d.Admin.QueryRow(ctx,
		`SELECT count(1)::int FROM pg_trigger WHERE tgname = 'basalt_guard'`).Scan(&triggers))
	require.Equal(t, 4, triggers)
	require.NoError(t, other.Conn.Ping(ctx))
}

func TestInitPicksUpNewCascade(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()

	d.Exec(t, `CREATE TABLE public.lead_files (id bigint PRIMARY KEY, lead_id bigint REFERENCES public.leads ON DELETE CASCADE)`)
	uncovered, err := guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, uncovered, 1)
	require.Equal(t, "lead_files", uncovered[0].Table)
	require.Contains(t, uncovered[0].Why, "CASCADE_TARGET via public.leads -> public.lead_files")

	d.Init(t, guard.AgentSpec{})
	uncovered, err = guard.UncoveredTables(ctx, a.Conn)
	require.NoError(t, err)
	require.Empty(t, uncovered)
}

func TestAttachRefusesTableWithoutPrimaryKey(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.nokey (a int, b text)`)
	err := d.TryInit(guard.AgentSpec{Name: "bot", Password: guard.NewPassword(), Write: []string{"nokey"}})
	require.Error(t, err)
	require.Equal(t, "BS007", guardtest.SQLState(err))
	require.ErrorContains(t, err, "NOT_ALLOWED")
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v, "init is one transaction: nothing installed")
}

func TestUninstallDropsSchemaAndRoles(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	require.NoError(t, a.Conn.Close(ctx))

	tx, err := d.Admin.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.Uninstall(ctx, tx, d.Names))
	require.NoError(t, tx.Commit(ctx))

	var schemas, roles, triggers int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_namespace WHERE nspname = 'basalt_meta'`).Scan(&schemas))
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_roles WHERE rolname LIKE $1`, d.Names.Prefix+`\_%`).Scan(&roles))
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_trigger WHERE tgname LIKE 'basalt_guard%'`).Scan(&triggers))
	require.Zero(t, schemas)
	require.Zero(t, roles)
	require.Zero(t, triggers)

	// Uninstalling twice is a no-op.
	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
}
