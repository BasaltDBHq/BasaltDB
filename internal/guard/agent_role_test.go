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

const scramPrefix = "SCRAM-SHA-256$4096:"

// requireSentAsVerifier plans init for spec and checks that no statement
// Postgres would receive (or log) holds the plaintext password, and that
// the role's password is set from a SCRAM verifier. It applies the plan.
func requireSentAsVerifier(t *testing.T, d *guardtest.DB, spec guard.AgentSpec) {
	t.Helper()
	ctx := context.Background()
	s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, Agent: spec})
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
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return s.Apply(ctx, tx) }))
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
	requireSentAsVerifier(t, d, guard.AgentSpec{Name: "bot", Password: pw, Write: leads, Read: leads})
	require.True(t, strings.HasPrefix(stored(), scramPrefix), "Postgres stored the verifier as given")
	requireLogin(t, d, pw)

	// --rotate-password on the role that exists.
	pw2 := guard.NewPassword()
	before := stored()
	requireSentAsVerifier(t, d, guard.AgentSpec{Name: "bot", Password: pw2, Write: leads, Read: leads})
	require.NotEqual(t, before, stored())
	requireLogin(t, d, pw2)
	requireNoLogin(t, d, "bot", pw)

	// CreateOnly with a generated password.
	pw3 := guard.NewPassword()
	requireSentAsVerifier(t, d, guard.AgentSpec{Name: "other", Password: pw3, CreateOnly: true, Write: leads})
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

	paths := map[string]func() guard.AgentSpec{
		"keep the password":   func() guard.AgentSpec { return guard.AgentSpec{Write: leads} },
		"rotate the password": func() guard.AgentSpec { return guard.AgentSpec{Password: guard.NewPassword(), Write: leads} },
		"setup code with a verifier": func() guard.AgentSpec {
			return guard.AgentSpec{Verifier: newVerifier(t, guard.NewPassword()), Write: leads}
		},
	}
	for path, spec := range paths {
		for _, name := range names {
			t.Run(path+"/"+name, func(t *testing.T) {
				role, err := d.Names.Agent(name)
				require.NoError(t, err)
				before := scalarOf[string](t, d.Admin, `SELECT coalesce(rolpassword, '') FROM pg_authid WHERE rolname = $1`, role)
				s := spec()
				s.Name = name
				err = d.TryInit(s)
				requireCode(t, err, guard.CodeLedgerInputInvalid)
				require.Equal(t, before, scalarOf[string](t, d.Admin,
					`SELECT coalesce(rolpassword, '') FROM pg_authid WHERE rolname = $1`, role), "nothing changed")
				require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM information_schema.table_privileges
					WHERE grantee = $1 AND table_name = 'leads'`, role), "no grant was made")
			})
		}
	}
}

func TestInitAdoptsAPlainExistingRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Init(t, guard.AgentSpec{})
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	// A role the person made by hand, with no rights of note.
	d.Exec(t, `CREATE ROLE `+role+` NOLOGIN`)
	pw := guard.NewPassword()
	d.Init(t, guard.AgentSpec{Name: "bot", Password: pw, Write: leads, Read: leads})
	requireLogin(t, d, pw)
	// Re-running init keeps the password and still passes the check.
	d.Init(t, guard.AgentSpec{Name: "bot", Write: leads, Read: leads})
	requireLogin(t, d, pw)
}
