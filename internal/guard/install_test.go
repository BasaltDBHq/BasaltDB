package guard_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
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
	const canary = "ADMINSECRET"
	cases := map[string]struct {
		admin, want, user string
		// parse: what pgx can parse here; the default is both strings.
		parse parsed
	}{
		"direct": {
			admin: "postgres://postgres:" + canary + "@db.abcd.supabase.co:5432/postgres?sslmode=require",
			want:  "postgres://basalt_agent_bot:pw@db.abcd.supabase.co:5432/postgres?sslmode=require",
			user:  "basalt_agent_bot",
			parse: parsedBoth,
		},
		"supabase pooler keeps the project ref": {
			admin: "postgresql://postgres.abcd:" + canary + "@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
			want:  "postgresql://basalt_agent_bot.abcd:pw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
			user:  "basalt_agent_bot.abcd",
		},
		"a dot elsewhere is part of the role": {
			admin: "postgres://ops.admin:" + canary + "@127.0.0.1:5432/app",
			want:  "postgres://basalt_agent_bot:pw@127.0.0.1:5432/app",
			user:  "basalt_agent_bot",
		},
		"no user": {
			admin: "postgres://127.0.0.1/app",
			want:  "postgres://basalt_agent_bot:pw@127.0.0.1/app",
			user:  "basalt_agent_bot",
		},
		"user and password in the query are dropped": {
			admin: "postgres://admin:pw0@db.example.com/app?user=admin&password=" + canary + "&sslmode=verify-full",
			want:  "postgres://basalt_agent_bot:pw@db.example.com/app?sslmode=verify-full",
			user:  "basalt_agent_bot",
		},
		"credentials only in the query are dropped": {
			admin: "postgres://db.example.com/app?user=admin&password=" + canary,
			want:  "postgres://basalt_agent_bot:pw@db.example.com/app",
			user:  "basalt_agent_bot",
		},
		"passfile and sslpassword are dropped": {
			admin: "postgres://admin@db.example.com/app?passfile=/home/admin/.pgpass&sslpassword=" + canary,
			want:  "postgres://basalt_agent_bot:pw@db.example.com/app",
			user:  "basalt_agent_bot",
		},
		"service and servicefile are dropped": {
			admin: "postgres://admin@db.example.com/app?service=" + canary + "&servicefile=/home/admin/.pg_service.conf",
			want:  "postgres://basalt_agent_bot:pw@db.example.com/app",
			user:  "basalt_agent_bot",
			parse: parsedAgent, // the service file does not exist
		},
		"runtime parameters are dropped": {
			admin: "postgres://admin:" + canary + "@db.example.com/app?options=-c%20role%3Dadmin&search_path=x",
			want:  "postgres://basalt_agent_bot:pw@db.example.com/app",
			user:  "basalt_agent_bot",
		},
		"a unix socket host and port in the query are kept": {
			admin: "postgres:///app?host=/var/run/postgresql&port=5433&user=admin&password=" + canary,
			want:  "postgres://basalt_agent_bot:pw@/app?host=%2Fvar%2Frun%2Fpostgresql&port=5433",
			user:  "basalt_agent_bot",
		},
		"dbname in the query is kept": {
			admin: "postgres://admin:" + canary + "@db.example.com?dbname=app",
			want:  "postgres://basalt_agent_bot:pw@db.example.com?dbname=app",
			user:  "basalt_agent_bot",
		},
		"the allowlisted parameters are kept": {
			admin: "postgres://admin:" + canary + "@db.example.com/app?sslmode=require&channel_binding=require" +
				"&target_session_attrs=read-write&connect_timeout=5&application_name=basalt&default_query_exec_mode=exec",
			want: "postgres://basalt_agent_bot:pw@db.example.com/app?application_name=basalt&channel_binding=require&connect_timeout=5" +
				"&default_query_exec_mode=exec&sslmode=require&target_session_attrs=read-write",
			user: "basalt_agent_bot",
		},
		"the admin's client certificate and key are dropped": {
			admin: "postgres://admin:" + canary + "@db.example.com/app?sslmode=verify-ca&sslrootcert=/etc/ssl/ca.pem&sslcrl=/etc/ssl/crl.pem" +
				"&sslcert=/home/admin/" + canary + ".crt&sslkey=/home/admin/" + canary + ".key&sslcertmode=require",
			want: "postgres://basalt_agent_bot:pw@db.example.com/app?sslcertmode=require&sslcrl=%2Fetc%2Fssl%2Fcrl.pem" +
				"&sslmode=verify-ca&sslrootcert=%2Fetc%2Fssl%2Fca.pem",
			user:  "basalt_agent_bot",
			parse: parsedNone, // the certificate files do not exist
		},
		"multiple hosts": {
			admin: "postgres://admin:" + canary + "@db1.example.com:5432,db2.example.com:5433/app?target_session_attrs=primary&password=" + canary,
			want:  "postgres://basalt_agent_bot:pw@db1.example.com:5432,db2.example.com:5433/app?target_session_attrs=primary",
			user:  "basalt_agent_bot",
		},
		"ipv6": {
			admin: "postgres://admin:" + canary + "@[::1]:5432/app?user=admin",
			want:  "postgres://basalt_agent_bot:pw@[::1]:5432/app",
			user:  "basalt_agent_bot",
		},
		"supabase pooler with credentials in the query": {
			admin: "postgres://postgres.abcd@aws-0-eu-central-1.pooler.supabase.com:6543/postgres?password=" + canary + "&user=postgres.abcd",
			want:  "postgres://basalt_agent_bot.abcd:pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres",
			user:  "basalt_agent_bot.abcd",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := guard.AgentConnString(c.admin, "basalt_agent_bot", "pw")
			require.NoError(t, err)
			require.Equal(t, c.want, got)
			require.NotContains(t, got, canary)
			require.NotContains(t, got, "admin")
			if c.parse == parsedNone {
				return
			}
			cfg, err := pgx.ParseConfig(got)
			require.NoError(t, err)
			require.Equal(t, c.user, cfg.User)
			require.Equal(t, "pw", cfg.Password)
			if c.parse == parsedAgent {
				return
			}
			adminCfg, err := pgx.ParseConfig(c.admin)
			require.NoError(t, err)
			require.Equal(t, route(adminCfg), route(cfg), "the agent connects where the admin does")
		})
	}
	for _, kv := range []string{
		"host=db user=postgres",
		"host=db user=admin password=" + canary + " dbname=app",
	} {
		_, err := guard.AgentConnString(kv, "basalt_agent_bot", "pw")
		require.ErrorIs(t, err, guard.ErrAdminURLForm, kv)
	}
	_, err := guard.AgentConnString("postgres://admin:"+canary+"@%2Fvar%2Frun%2Fpostgresql/app", "basalt_agent_bot", "pw")
	require.ErrorIs(t, err, guard.ErrAdminURLParse)
	require.NotContains(t, err.Error(), canary)
}

// parsed is what pgx can parse in a TestAgentConnString case.
type parsed int

const (
	parsedBoth  parsed = iota // the admin's and the agent's strings
	parsedAgent               // the agent's only
	parsedNone                // neither
)

// route is where a pgx config connects: every host and port, and the
// database.
func route(cfg *pgx.ConnConfig) []string {
	r := make([]string, 0, 2+len(cfg.Fallbacks))
	r = append(r, cfg.Database, fmt.Sprintf("%s:%d", cfg.Host, cfg.Port))
	for _, f := range cfg.Fallbacks {
		r = append(r, fmt.Sprintf("%s:%d", f.Host, f.Port))
	}
	return r
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
