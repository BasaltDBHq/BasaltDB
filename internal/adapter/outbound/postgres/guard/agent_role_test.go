package guard_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

const scramPrefix = "SCRAM-SHA-256$4096:"

// requireSentAsVerifier plans init for spec and checks that no statement
// Postgres would receive (or log) holds the plaintext password, and that
// the role's password is set from a SCRAM verifier. It applies the plan.
func requireSentAsVerifier(t *testing.T, d *guardtest.DB, spec guardmodel.AgentSpec) {
	t.Helper()
	ctx := context.Background()
	s, err := guard.PlanInit(ctx, d.Admin, guardmodel.InitOptions{Names: d.Names, Agent: spec})
	require.NoError(t, err)
	var sent strings.Builder
	for _, st := range s.Statements {
		sent.WriteString(st.SQL)
		sent.WriteString(st.Shown)
	}
	require.NotContains(t, sent.String(), spec.Password, "the plaintext password never reaches Postgres")
	require.Contains(t, sent.String(), "PASSWORD '"+scramPrefix)
	require.Contains(t, s.SQL(), "PASSWORD '********'", "the person sees the verifier redacted")
	require.NotContains(t, s.SQL(), scramPrefix)
	// Roles are cluster-wide: a parallel test can deadlock the role catalog.
	require.NoError(t, guardtest.RetryDeadlock(func() error {
		return pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return guard.ApplyScript(ctx, tx, s) })
	}))
}

func TestInitSendsVerifierNotPassword(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	stored := func() string {
		return scalarOf[string](t, d.Admin, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, role)
	}

	// A new role.
	pw := guard.NewPassword()
	requireSentAsVerifier(t, d, guardmodel.AgentSpec{Name: "bot", Password: pw, Write: leads, Read: leads})
	require.True(t, strings.HasPrefix(stored(), scramPrefix), "Postgres stored the verifier as given")
	requireLogin(t, d, pw)

	// --rotate-password on the role that exists.
	pw2 := guard.NewPassword()
	before := stored()
	requireSentAsVerifier(t, d, guardmodel.AgentSpec{Name: "bot", Password: pw2, Write: leads, Read: leads})
	require.NotEqual(t, before, stored())
	requireLogin(t, d, pw2)
	requireNoLogin(t, d, "bot", pw)

	// CreateOnly with a generated password.
	pw3 := guard.NewPassword()
	requireSentAsVerifier(t, d, guardmodel.AgentSpec{Name: "other", Password: pw3, CreateOnly: true, Write: leads})
	c, err := connectAs(context.Background(), d, "other", pw3)
	require.NoError(t, err)
	require.NoError(t, c.Close(context.Background()))
}

// elevatedRoles makes one <prefix>_agent_<name> role per way a role is not
// a plain agent, each a member of the agents group (as a role from an
// earlier init would be), and returns their names.
func elevatedRoles(t *testing.T, d *guardtest.DB) []string {
	t.Helper()
	agentRole := func(name string) string {
		r, err := d.Names.Agent(name)
		require.NoError(t, err)
		return r
	}
	boss := d.Names.Prefix + "_boss"
	d.Exec(t, `CREATE ROLE `+boss+` NOLOGIN CREATEROLE`)
	reader := d.Names.Prefix + "_reader"
	d.Exec(t, `CREATE ROLE `+reader+` NOLOGIN`)
	d.Exec(t, `GRANT pg_read_all_data TO `+reader)
	friends := d.Names.Prefix + "_friends"
	d.Exec(t, `CREATE ROLE `+friends+` NOLOGIN`)
	fixtures := map[string]string{
		"super":      `CREATE ROLE %[1]s LOGIN SUPERUSER`,
		"maker":      `CREATE ROLE %[1]s LOGIN CREATEROLE`,
		"bypass":     `CREATE ROLE %[1]s LOGIN BYPASSRLS`,
		"dbmaker":    `CREATE ROLE %[1]s LOGIN CREATEDB`,
		"replicator": `CREATE ROLE %[1]s LOGIN REPLICATION`,
		"writeall":   `CREATE ROLE %[1]s LOGIN; GRANT pg_write_all_data TO %[1]s`,
		"readall":    `CREATE ROLE %[1]s LOGIN; GRANT pg_read_all_data TO %[1]s`,
		"files":      `CREATE ROLE %[1]s LOGIN; GRANT pg_read_server_files TO %[1]s`,
		"guardian":   `CREATE ROLE %[1]s LOGIN; GRANT ` + d.Names.Guard() + ` TO %[1]s`,
		// Not inheriting: it can still SET ROLE to the elevated group.
		"underboss": `CREATE ROLE %[1]s LOGIN NOINHERIT; GRANT ` + boss + ` TO %[1]s`,
		// Indirect: a member of a member of pg_read_all_data.
		"indirect": `CREATE ROLE %[1]s LOGIN; GRANT ` + reader + ` TO %[1]s`,
		// Memberships are an allow-list: anything but the agents group.
		"monitor": `CREATE ROLE %[1]s LOGIN; GRANT pg_monitor TO %[1]s`,
		"signal":  `CREATE ROLE %[1]s LOGIN; GRANT pg_signal_backend TO %[1]s`,
		"friend":  `CREATE ROLE %[1]s LOGIN; GRANT ` + friends + ` TO %[1]s`,
		// Direct privileges that let it get around the guard.
		"truncator":  `CREATE ROLE %[1]s LOGIN; GRANT TRUNCATE ON public.leads TO %[1]s`,
		"triggerer":  `CREATE ROLE %[1]s LOGIN; GRANT TRIGGER ON public.lead_notes TO %[1]s`, // guarded, not its own
		"referencer": `CREATE ROLE %[1]s LOGIN; GRANT REFERENCES ON public.leads TO %[1]s`,
		"metareader": `CREATE ROLE %[1]s LOGIN; GRANT SELECT ON basalt_meta.ledger TO %[1]s`,
		"metausage":  `CREATE ROLE %[1]s LOGIN; GRANT USAGE ON SCHEMA basalt_meta TO %[1]s`,
		"metacaller": `CREATE ROLE %[1]s LOGIN; GRANT EXECUTE ON FUNCTION basalt_meta.verify_chain() TO %[1]s`,
	}
	names := make([]string, 0, len(fixtures))
	for name, sql := range fixtures {
		role := agentRole(name)
		d.Exec(t, fmt.Sprintf(sql, role))
		d.Exec(t, `GRANT `+d.Names.Agents()+` TO `+role)
		names = append(names, name)
	}
	return names
}

func TestInitRefusesToAdoptAnElevatedRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads) // the guard and the guard role exist
	names := elevatedRoles(t, d)

	paths := map[string]func() guardmodel.AgentSpec{
		"keep the password":   func() guardmodel.AgentSpec { return guardmodel.AgentSpec{Write: leads} },
		"rotate the password": func() guardmodel.AgentSpec { return guardmodel.AgentSpec{Password: guard.NewPassword(), Write: leads} },
		"setup code with a verifier": func() guardmodel.AgentSpec {
			return guardmodel.AgentSpec{Verifier: newVerifier(t, guard.NewPassword()), Write: leads}
		},
	}
	for path, spec := range paths {
		for _, name := range names {
			t.Run(path+"/"+name, func(t *testing.T) {
				role, err := d.Names.Agent(name)
				require.NoError(t, err)
				state := func() string {
					return scalarOf[string](t, d.Admin, `SELECT coalesce(a.rolpassword, '') || a.rolcanlogin::text ||
						(SELECT count(1) FROM information_schema.table_privileges p WHERE p.grantee = a.rolname)::text
						FROM pg_authid a WHERE a.rolname = $1`, role)
				}
				before := state()
				s := spec()
				s.Name = name
				err = d.TryInit(s)
				requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
				require.Equal(t, before, state(), "nothing changed")
			})
		}
	}
}

func TestInitAdoptsAPlainExistingRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Init(t, guardmodel.AgentSpec{})
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	// A role the person made by hand, with no rights of note.
	d.Exec(t, `CREATE ROLE `+role+` NOLOGIN`)
	pw := guard.NewPassword()
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Password: pw, Write: leads, Read: leads})
	requireLogin(t, d, pw)
	// Re-running init keeps the password and still passes the check.
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Write: leads, Read: leads})
	requireLogin(t, d, pw)
}

func TestInitRefusesAnAgentThatOwns(t *testing.T) {
	t.Parallel()
	for name, own := range map[string]func(t *testing.T, d *guardtest.DB, role string){
		"an agent table": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `ALTER TABLE public.leads OWNER TO `+role)
		},
		"a guarded table": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `ALTER TABLE public.lead_notes OWNER TO `+role)
		},
		"the table schema": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `ALTER SCHEMA public OWNER TO `+role)
		},
		"the database": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `ALTER DATABASE `+pgx.Identifier{d.Admin.Config().Database}.Sanitize()+` OWNER TO `+role)
		},
		// Any object: its owner could replace it and run code as whoever
		// writes the guarded table next.
		"a trigger function": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
			d.Exec(t, `CREATE TRIGGER touch BEFORE UPDATE ON public.leads FOR EACH ROW EXECUTE FUNCTION public.touch()`)
			d.Exec(t, `ALTER FUNCTION public.touch() OWNER TO `+role)
		},
		"a default's function": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `CREATE FUNCTION public.zero() RETURNS int LANGUAGE sql AS $$ SELECT 0 $$`)
			d.Exec(t, `ALTER TABLE public.leads ALTER COLUMN score SET DEFAULT public.zero()`)
			d.Exec(t, `ALTER FUNCTION public.zero() OWNER TO `+role)
		},
		"a view": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `CREATE VIEW public.lead_view AS SELECT id FROM public.leads`)
			d.Exec(t, `ALTER VIEW public.lead_view OWNER TO `+role)
		},
		"a sequence": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `CREATE SEQUENCE public.lead_seq`)
			d.Exec(t, `ALTER SEQUENCE public.lead_seq OWNER TO `+role)
		},
		// A member of the owner, not the owner itself.
		"through a group": func(t *testing.T, d *guardtest.DB, role string) {
			d.Exec(t, `CREATE ROLE `+d.Names.Prefix+`_owners NOLOGIN`)
			d.Exec(t, `ALTER TABLE public.leads OWNER TO `+d.Names.Prefix+`_owners`)
			d.Exec(t, `GRANT `+d.Names.Prefix+`_owners TO `+role)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			d.NewAgent(t, "bot", leads, leads)
			role, err := d.Names.Agent("bot")
			require.NoError(t, err)
			own(t, d, role)
			for _, spec := range []guardmodel.AgentSpec{
				{Name: "bot", Write: leads, Read: leads},
				{Name: "bot", Password: guard.NewPassword(), Write: leads, Read: leads},
			} {
				requireCode(t, d.TryInit(spec), guardmodel.CodeLedgerInputInvalid)
			}
		})
	}
}

func TestInitResetsTheRoleSettings(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{})
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	// A superuser once set replica mode on the role: the guard's triggers
	// would not fire for its sessions.
	d.Exec(t, `CREATE ROLE `+role+` NOLOGIN`)
	d.Exec(t, `ALTER ROLE `+role+` SET session_replication_role = replica`)
	d.Exec(t, `ALTER ROLE `+role+` IN DATABASE `+pgx.Identifier{d.Admin.Config().Database}.Sanitize()+
		` SET session_replication_role = replica`)

	pw := guard.NewPassword()
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Password: pw, Write: leads, Read: leads})
	require.Equal(t, []string{"statement_timeout=30000"}, scalarOf[[]string](t, d.Admin,
		`SELECT array_agg(c ORDER BY c) FROM pg_db_role_setting s, unnest(s.setconfig) c
		WHERE s.setrole = $1::regrole`, role))
	bot := requireLogin(t, d, pw)
	require.Equal(t, "origin", scalarOf[string](t, bot, `SHOW session_replication_role`))
	_, err = bot.Exec(ctx, `UPDATE public.leads SET status = 'merged' WHERE id = 4`)
	requireCode(t, err, guardmodel.CodeIntentRequired)

	// Keeping the password resets them too.
	d.Exec(t, `ALTER ROLE `+role+` SET session_replication_role = replica`)
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Write: leads, Read: leads})
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM pg_db_role_setting s, unnest(s.setconfig) c
		WHERE s.setrole = $1::regrole AND c LIKE 'session_replication_role%'`, role))
}

func TestInitRefusesSettingsTheAdminCannotReset(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{})
	// An admin that is not a superuser (as on a hosted Postgres) created the
	// agent role; a superuser then set a setting only a superuser may set.
	admin := d.Names.Prefix + "_admin"
	pw := guard.NewPassword()
	d.Exec(t, `CREATE ROLE `+admin+` LOGIN CREATEROLE PASSWORD '`+pw+`'`)
	dsn, err := guard.AgentConnString(d.URL, admin, pw)
	require.NoError(t, err)
	c, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	_, err = c.Exec(ctx, `CREATE ROLE `+role+` NOLOGIN`)
	require.NoError(t, err)
	d.Exec(t, `ALTER ROLE `+role+` SET session_replication_role = replica`)

	sql, err := guard.AgentAdoptSQL(d.Names, "bot", guardmodel.AgentSpec{Write: leads})
	require.NoError(t, err)
	_, err = c.Exec(ctx, sql)
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM pg_db_role_setting s, unnest(s.setconfig) c
		WHERE s.setrole = $1::regrole AND c = 'session_replication_role=replica'`, role))
}
