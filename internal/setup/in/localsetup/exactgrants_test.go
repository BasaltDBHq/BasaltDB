package localsetup_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

func writePick(table string) localsetup.TablePick {
	return localsetup.TablePick{Table: table, Access: localsetup.AccessWrite}
}

// directGrants are the privileges role holds directly on each relation of
// schema public, tables and sequences, as "relation:PRIVILEGE".
func directGrants(t *testing.T, f *fixture, role string) []string {
	t.Helper()
	ctx := context.Background()
	// Plain SQL: test catalog read.
	rows, err := f.db.Admin.Query(ctx, `SELECT c.relname || ':' || a.privilege_type
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
		JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
		WHERE n.nspname = 'public' AND r.rolname = $1`, role)
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

// interruptedInstall runs a real install of tables whose database part
// commits but whose engine.json write fails, as an install the person
// stopped half way: the role keeps the grants and this engine its
// credential.
func interruptedInstall(t *testing.T, f *fixture, tables []localsetup.TablePick) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Dir(f.config)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "agents"), 0o700))
	req := f.real()
	req.Tables = tables
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	require.NoError(t, os.Chmod(dir, 0o500))
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, os.Chmod(dir, 0o700))
	refusal(t, err, localsetup.CodeSetupFailed)
	require.True(t, exists(t, f.db, "basalt_meta"), "the database part committed")
}

// finishInstall checks and runs a real install of tables with the role an
// interrupted run left, and returns the SQL the check showed.
func finishInstall(t *testing.T, f *fixture, tables []localsetup.TablePick) string {
	t.Helper()
	ctx := context.Background()
	req := f.real()
	req.Tables = tables
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.False(t, checked.PasskeyNeeded, "the passkey committed with the role")
	req.Challenge = checked.Challenge
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	return checked.SQL
}

// An install finished after an interrupted one leaves the role with grants
// on exactly the tables picked now: the earlier run's grants on tables not
// picked now are revoked, write privileges on a table now picked to read
// too, and the serial sequence goes with its write grant. A grant the setup
// never makes (a column privilege) stays.
func TestFinishedInstallRevokesTheGrantsOfTablesNotPickedNow(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder without write permission")
	}
	cases := map[string]struct {
		earlier, now []localsetup.TablePick
		want         []string
		cannot       []string
	}{
		"t1 and t2, then t1 only": {
			earlier: picks(readPick("public.t1"), writePick("public.t2")),
			now:     picks(readPick("public.t1")),
			want:    []string{"t1:SELECT"},
			cannot:  []string{"public.t2"},
		},
		"t1 and t2, then t2 and t3": {
			earlier: picks(readPick("public.t1"), writePick("public.t2")),
			now:     picks(readPick("public.t2"), readPick("public.t3")),
			want:    []string{"t2:SELECT", "t3:SELECT"},
			cannot:  []string{"public.t1"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			role := f.db.Names.Prefix + "_agent_bot"
			f.db.Exec(t, exactTables)
			interruptedInstall(t, f, c.earlier)
			require.True(t, can(t, f, role, "public.t1", "SELECT"), "the interrupted run granted t1")
			require.True(t, can(t, f, role, "public.t2", "INSERT"), "the interrupted run granted t2")
			// A grant the setup never makes: it must stay.
			f.db.Exec(t, `GRANT SELECT (note) ON public.other TO `+role)

			shown := finishInstall(t, f, c.now)
			require.Contains(t, shown, exactMarker, "the finish shows the revoke")

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

// A fresh install (no earlier run) is unchanged: its SQL revokes nothing
// and the role gets the picked tables.
func TestFreshInstallRevokesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	role := f.db.Names.Prefix + "_agent_bot"
	f.db.Exec(t, exactTables)
	req := f.real()
	req.Tables = picks(readPick("public.t1"), writePick("public.t2"))
	checked, err := f.svc.Check(ctx, req)
	require.NoError(t, err)
	require.NotContains(t, checked.SQL, exactMarker, "a new role has nothing to revoke")
	req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
	_, err = f.svc.Run(ctx, req)
	require.NoError(t, err)
	require.Equal(t, []string{"t1:SELECT", "t2:DELETE", "t2:INSERT", "t2:SELECT", "t2:UPDATE", "t2_id_seq:SELECT", "t2_id_seq:USAGE"},
		directGrants(t, f, role))
	require.False(t, can(t, f, role, "public.t3", "SELECT"))
}
