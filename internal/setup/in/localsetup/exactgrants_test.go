package localsetup_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// exactMarker is a line only the statement that revokes an earlier run's
// grants holds.
const exactMarker = "v_write oid[]"

// exactTables are the tables these tests pick from: t2 has a serial
// sequence, which a write grant reaches too.
const exactTables = `CREATE TABLE public.t1 (id bigint PRIMARY KEY, note text);
CREATE TABLE public.t2 (id bigserial PRIMARY KEY, note text);
CREATE TABLE public.t3 (id bigint PRIMARY KEY, note text);
CREATE TABLE public.other (id bigint PRIMARY KEY, note text)`

func picks(p ...localsetup.TablePick) []localsetup.TablePick { return p }

func readPick(table string) localsetup.TablePick {
	return localsetup.TablePick{Table: table, Access: localsetup.AccessRead}
}

// writeT2 picks t2 to write.
var writeT2 = localsetup.TablePick{Table: "public.t2", Access: localsetup.AccessWrite}

// realReq is a real install request for tables in schemas (nil: public).
func (f *fixture) realReq(schemas []string, tables []localsetup.TablePick) localsetup.Request {
	r := f.real()
	r.Schemas, r.Tables = schemas, tables
	return r
}

// directGrants are the privileges role holds directly on each relation
// outside the system schemas, tables and sequences, as
// "schema.relation:PRIVILEGE", sorted.
func directGrants(t *testing.T, f *fixture, role string) []string {
	t.Helper()
	ctx := context.Background()
	// Plain SQL: test catalog read.
	rows, err := f.db.Admin.Query(ctx, `SELECT n.nspname || '.' || c.relname || ':' || a.privilege_type
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
		JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
		WHERE n.nspname !~ '^pg_' AND n.nspname NOT IN ('information_schema', 'basalt_meta') AND r.rolname = $1`, role)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	slices.Sort(out)
	return out
}

// can reports has_table_privilege for role on table.
func can(t *testing.T, f *fixture, role, table, privilege string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, f.db.Admin.QueryRow(context.Background(),
		`SELECT pg_catalog.has_table_privilege($1, $2, $3)`, role, table, privilege).Scan(&ok))
	return ok
}

// interruptedInstall runs req, a real install whose database part commits
// but whose engine.json write fails, as an install the person stopped half
// way: the role keeps the grants and this engine its credential.
func interruptedInstall(t *testing.T, f *fixture, req localsetup.Request) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder without write permission")
	}
	ctx := context.Background()
	dir := filepath.Dir(f.config)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "agents"), 0o700))
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	require.NoError(t, os.Chmod(dir, 0o500))
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, os.Chmod(dir, 0o700))
	refusal(t, err, localsetup.CodeSetupFailed)
	require.True(t, exists(t, f.db, "basalt_meta"), "the database part committed")
}

// finishInstall checks and runs req with the role an earlier run left, and
// returns the check's answer and the run's error.
func finishInstall(t *testing.T, f *fixture, req localsetup.Request) (localsetup.CheckAnswer, error) {
	t.Helper()
	ctx := context.Background()
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	if checked.PasskeyNeeded {
		req.Passkey = register(t, *checked.Challenge)
	}
	req.Challenge = checked.Challenge
	_, err = f.svc.Run(ctx, req)
	return checked, err
}

// An install finished after an interrupted one leaves the role with grants
// on exactly the tables picked now: the earlier run's grants on tables not
// picked now are revoked, write privileges on a table now picked to read
// too, and the serial sequence goes with its write grant. A grant the setup
// never makes (a column privilege) stays.
func TestFinishedInstallRevokesTheGrantsOfTablesNotPickedNow(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		earlier, now []localsetup.TablePick
		want         []string
		cannot       []string
	}{
		"t1 and t2, then t1 only": {
			earlier: picks(readPick("public.t1"), writeT2),
			now:     picks(readPick("public.t1")),
			want:    []string{"public.t1:SELECT"},
			cannot:  []string{"public.t2"},
		},
		"t1 and t2, then t2 and t3": {
			earlier: picks(readPick("public.t1"), writeT2),
			now:     picks(readPick("public.t2"), readPick("public.t3")),
			want:    []string{"public.t2:SELECT", "public.t3:SELECT"},
			cannot:  []string{"public.t1"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			role := f.db.Names.Prefix + "_agent_bot"
			f.db.Exec(t, exactTables)
			interruptedInstall(t, f, f.realReq(nil, c.earlier))
			require.True(t, can(t, f, role, "public.t1", "SELECT"), "the interrupted run granted t1")
			require.True(t, can(t, f, role, "public.t2", "INSERT"), "the interrupted run granted t2")
			// A grant the setup never makes: it must stay.
			f.db.Exec(t, `GRANT SELECT (note) ON public.other TO `+role)

			checked, err := finishInstall(t, f, f.realReq(nil, c.now))
			require.NoError(t, err)
			require.False(t, checked.PasskeyNeeded, "the passkey committed with the role")
			require.Contains(t, checked.SQL, exactMarker, "the finish shows the revoke")

			require.Equal(t, c.want, directGrants(t, f, role), "exactly the tables picked now")
			for _, table := range c.cannot {
				require.False(t, can(t, f, role, table, "SELECT"), "%s is not picked now", table)
			}
			require.False(t, can(t, f, role, "public.t2", "INSERT"), "t2 is not picked to write now")
			var seq bool
			require.NoError(t, f.db.Admin.QueryRow(context.Background(),
				`SELECT pg_catalog.has_sequence_privilege($1, 'public.t2_id_seq', 'USAGE')`, role).Scan(&seq))
			require.False(t, seq, "the sequence goes with t2's write grant")
			var column bool
			require.NoError(t, f.db.Admin.QueryRow(context.Background(),
				`SELECT pg_catalog.has_column_privilege($1, 'public.other', 'note', 'SELECT')`, role).Scan(&column))
			require.True(t, column, "a grant the setup never makes stays")
		})
	}
}

// The revoke reaches every schema the page can list, not only this run's:
// an interrupted run that listed schema sa, then a finish that lists only
// public, leaves nothing on sa's table.
func TestFinishedInstallRevokesGrantsInASchemaNotListedNow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	role := f.db.Names.Prefix + "_agent_bot"
	f.db.Exec(t, exactTables+`;
CREATE SCHEMA sa;
CREATE TABLE sa.x (id bigint PRIMARY KEY)`)
	interruptedInstall(t, f, f.realReq([]string{"sa"}, picks(readPick("sa.x"))))
	require.True(t, can(t, f, role, "sa.x", "SELECT"), "the interrupted run granted sa.x")

	_, err := finishInstall(t, f, f.realReq(nil, picks(readPick("public.t1"))))
	require.NoError(t, err)
	require.Equal(t, []string{"public.t1:SELECT"}, directGrants(t, f, role))
	require.False(t, can(t, f, role, "sa.x", "SELECT"), "sa.x is not picked now")
}

// An install over a role a reset setup left behind (rekey: a new password)
// revokes that setup's grants on tables not picked now, as a finish does.
func TestReinstallAfterAResetRevokesTheGrantsOfTablesNotPickedNow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_bot"
	f.db.Exec(t, exactTables)
	first := f.realReq(nil, picks(readPick("public.t1"), writeT2))
	checked, err := f.svc.Check(ctx, first)
	require.NoError(t, err)
	first.Challenge, first.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, first)
	require.NoError(t, err)
	require.True(t, can(t, f, role, "public.t2", "INSERT"))

	// What the reset script does as root: the role stays in the database.
	require.NoError(t, os.Remove(f.config))
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(f.config), "agents", "bot.url")))

	checked, err = finishInstall(t, f, f.realReq(nil, picks(readPick("public.t1"))))
	require.NoError(t, err)
	require.Contains(t, strings.Join(checked.Lines, "\n"), "from an earlier setup", "the role is rekeyed")
	require.Contains(t, checked.SQL, exactMarker, "the rekey shows the revoke")
	require.Equal(t, []string{"public.t1:SELECT"}, directGrants(t, f, role))
	require.False(t, can(t, f, role, "public.t2", "SELECT"))
}

// A grant from an earlier run on a table another role owns now cannot be
// revoked by this admin: the finish is refused GRANTS_NOT_REVOKED, naming
// the role and the table, and nothing changes.
func TestFinishedInstallRefusesGrantsItCannotRevoke(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_bot"
	owner := f.db.Names.Prefix + "_owner"
	f.db.Exec(t, exactTables)
	interruptedInstall(t, f, f.realReq(nil, picks(readPick("public.t1"), writeT2)))
	// Another role owns t2 now; its grants to the agent stay.
	f.db.Exec(t, `CREATE ROLE `+owner+` NOLOGIN;
GRANT `+owner+` TO CURRENT_USER;
GRANT CREATE ON SCHEMA public TO `+owner+`;
ALTER TABLE public.t2 OWNER TO `+owner)
	before := directGrants(t, f, role)
	require.Contains(t, before, "public.t2:SELECT")
	var settings, after string
	roleState := `SELECT r.rolcanlogin::text || r.rolconnlimit::text || coalesce(r.rolconfig::text, '') FROM pg_catalog.pg_roles r WHERE r.rolname = $1`
	require.NoError(t, f.db.Admin.QueryRow(ctx, roleState, role).Scan(&settings))

	_, err := finishInstall(t, f, f.realReq(nil, picks(readPick("public.t1"))))
	refusal(t, err, localsetup.CodeGrantsNotRevoked)
	require.Contains(t, err.Error(), "The agent role "+role+" still has access to tables that were not picked")
	require.Contains(t, err.Error(), "public.t2")
	require.Contains(t, err.Error(), "Nothing changed.")

	require.Equal(t, before, directGrants(t, f, role), "the grants are as before")
	require.NoError(t, f.db.Admin.QueryRow(ctx, roleState, role).Scan(&after))
	require.Equal(t, settings, after, "the role is unchanged")
	_, statErr := os.Stat(f.config)
	require.ErrorIs(t, statErr, os.ErrNotExist, "the engine is not set up")
}

// A fresh install (no earlier run) is unchanged: its SQL revokes nothing
// and the role gets the picked tables.
func TestFreshInstallRevokesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_bot"
	f.db.Exec(t, exactTables)
	req := f.realReq(nil, picks(readPick("public.t1"), writeT2))
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.NotContains(t, checked.SQL, exactMarker, "a new role has nothing to revoke")
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, []string{
		"public.t1:SELECT", "public.t2:DELETE", "public.t2:INSERT", "public.t2:SELECT", "public.t2:UPDATE",
		"public.t2_id_seq:SELECT", "public.t2_id_seq:USAGE",
	}, directGrants(t, f, role))
	require.False(t, can(t, f, role, "public.t3", "SELECT"))
}
