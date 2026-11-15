package guard_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// installRow is basalt_meta.installs' row for install, read as the admin.
type installRow struct {
	At        time.Time
	By        string
	VaultUser *string
}

func readInstall(t *testing.T, d *guardtest.DB, install uint32) (installRow, bool) {
	t.Helper()
	var r installRow
	// Plain SQL: a fixture read of the guard's own table.
	err := d.Admin.QueryRow(context.Background(), `SELECT installed_at, installed_by::text, vault_user
		FROM basalt_meta.installs WHERE install = $1`, install).Scan(&r.At, &r.By, &r.VaultUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return installRow{}, false
	}
	require.NoError(t, err)
	return r, true
}

func adminUser(t *testing.T, d *guardtest.DB) string {
	t.Helper()
	var u string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT session_user::text`).Scan(&u))
	return u
}

// Every install writes its row in the install transaction; running the
// install again keeps it; a new install (after basalt uninstall) gets a new
// oid and its own row.
func TestInstallsRecordsEachInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	install, err := guard.InstallID(ctx, d.Admin)
	require.NoError(t, err)
	first, ok := readInstall(t, d, install)
	require.True(t, ok)
	require.Equal(t, adminUser(t, d), first.By)
	require.Nil(t, first.VaultUser)

	d.NewAgent(t, "bot", leads, nil)
	again, ok := readInstall(t, d, install)
	require.True(t, ok)
	require.True(t, first.At.Equal(again.At), "running the install again keeps the row")
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(install)::int FROM basalt_meta.installs`))

	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
	d.NewAgent(t, "bot", leads, nil)
	next, err := guard.InstallID(ctx, d.Admin)
	require.NoError(t, err)
	require.NotEqual(t, install, next)
	_, ok = readInstall(t, d, next)
	require.True(t, ok)
}

// The Vault's install path sets basalt.vault_user in the install
// transaction; installs keeps it.
func TestInstallsKeepsTheVaultUser(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('basalt.vault_user', 'alice@example.com', true)`); err != nil {
			return err
		}
		return s.Apply(ctx, tx)
	}))
	install, err := guard.InstallID(ctx, d.Admin)
	require.NoError(t, err)
	row, ok := readInstall(t, d, install)
	require.True(t, ok)
	require.NotNil(t, row.VaultUser)
	require.Equal(t, "alice@example.com", *row.VaultUser)
}

// An upgrade keeps the install's row as the install wrote it: every init
// records the install, and changes nothing for one that has its row.
func TestUpgradeKeepsTheInstall(t *testing.T) {
	d := guardtest.New(t).WithDemo(t)
	next := guardtest.NextVersion(t, false)
	ctx := context.Background()
	apply := func(upTo int) {
		s, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, UpTo: upTo})
		require.NoError(t, err)
		require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return s.Apply(ctx, tx) }))
	}
	apply(next - 1)
	install, err := guard.InstallID(ctx, d.Admin)
	require.NoError(t, err)
	before, ok := readInstall(t, d, install)
	require.True(t, ok)

	apply(0)
	require.Equal(t, next, scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
	after, ok := readInstall(t, d, install)
	require.True(t, ok)
	require.Equal(t, before, after)
}

// After a pg_restore installs has no row for the new schema: the next
// basalt init writes one with its own time and user.
func TestInitAfterARestoreWritesTheInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	d.Exec(t, `DELETE FROM basalt_meta.installs`)
	d.NewAgent(t, "bot", leads, nil)
	install, err := guard.InstallID(context.Background(), d.Admin)
	require.NoError(t, err)
	_, ok := readInstall(t, d, install)
	require.True(t, ok)
}

func requirePermissionDenied(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, "42501", guardtest.SQLState(err), err.Error())
}

// No agent role may write installs, or read it but through the notice's
// view.
func TestAgentCannotTouchInstalls(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	for _, sql := range []string{
		`INSERT INTO basalt_meta.installs VALUES (1, now(), 'mallory', 'mallory')`,
		`UPDATE basalt_meta.installs SET installed_by = 'mallory'`,
		`DELETE FROM basalt_meta.installs`,
		`SELECT 1 FROM basalt_meta.installs`,
	} {
		_, err := a.Conn.Exec(ctx, sql)
		requirePermissionDenied(t, err)
	}
}

func requireDetail(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	require.Equal(t, detail, pg.Detail)
}

// reinstallRow is one row of agent_reinstalls.
type reinstallRow struct {
	At            time.Time
	Agent         string
	PinnedSeq     int64
	PinnedHash    []byte
	PinnedInstall uint32
	Install       uint32
	InstalledAt   *time.Time
	InstalledBy   *string
	VaultUser     *string
}

func readReinstallRows(t *testing.T, q guard.Querier) []reinstallRow {
	t.Helper()
	// Plain SQL: a fixture read of the view, oldest first.
	rows, err := q.Query(context.Background(), `SELECT at, agent::text, pinned_seq, pinned_hash, pinned_install, install,
		installed_at, installed_by, vault_user FROM basalt_meta.agent_reinstalls ORDER BY at`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[reinstallRow])
	require.NoError(t, err)
	return out
}

// record_pin_set_aside, called as an agent role: refusals, the row it
// appends, idempotence per role, install and pin, and a database whose
// installs has no row for it.
func TestRecordPinSetAside(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	current, err := guard.InstallID(ctx, a.Conn)
	require.NoError(t, err)
	pin := guard.ChainHead{Seq: 41, Hash: bytes.Repeat([]byte{7}, 32)}

	_, err = guard.RecordPinSetAside(ctx, a.Conn, pin, current)
	requireDetail(t, err, "PIN_SAME_INSTALL")
	_, err = guard.RecordPinSetAside(ctx, a.Conn, guard.ChainHead{Seq: -1, Hash: pin.Hash}, current+1)
	requireDetail(t, err, "PIN_SHAPE")
	_, err = guard.RecordPinSetAside(ctx, a.Conn, guard.ChainHead{Seq: 1, Hash: pin.Hash[:31]}, current+1)
	requireDetail(t, err, "PIN_SHAPE")
	require.Empty(t, readReinstallRows(t, a.Conn), "a refusal writes nothing")

	old := current + 1000
	appended, err := guard.RecordPinSetAside(ctx, a.Conn, pin, old)
	require.NoError(t, err)
	require.True(t, appended)
	appended, err = guard.RecordPinSetAside(ctx, a.Conn, pin, old)
	require.NoError(t, err)
	require.False(t, appended, "the same report again appends nothing")

	rows := readReinstallRows(t, a.Conn)
	require.Len(t, rows, 1)
	r := rows[0]
	require.Equal(t, a.Role, r.Agent)
	require.Equal(t, pin.Seq, r.PinnedSeq)
	require.Equal(t, pin.Hash, r.PinnedHash)
	require.Equal(t, old, r.PinnedInstall)
	require.Equal(t, current, r.Install)
	inst, ok := readInstall(t, d, current)
	require.True(t, ok)
	require.NotNil(t, r.InstalledAt)
	require.True(t, inst.At.Equal(*r.InstalledAt), "the install's row is copied in")
	require.Equal(t, adminUser(t, d), *r.InstalledBy)
	require.Nil(t, r.VaultUser)

	// Another agent sees the report, and its own report of the same pin is
	// its own row: no report replaces another.
	b := d.NewAgent(t, "other", leads, nil)
	require.Len(t, readReinstallRows(t, b.Conn), 1)
	appended, err = guard.RecordPinSetAside(ctx, b.Conn, pin, old)
	require.NoError(t, err)
	require.True(t, appended)
	require.Len(t, readReinstallRows(t, a.Conn), 2)

	// basalt_meta recreated outside the install: no install fields.
	d.Exec(t, `DELETE FROM basalt_meta.installs`)
	appended, err = guard.RecordPinSetAside(ctx, a.Conn, guard.ChainHead{Seq: 42, Hash: pin.Hash}, old)
	require.NoError(t, err)
	require.True(t, appended)
	rows = readReinstallRows(t, a.Conn)
	last := rows[len(rows)-1]
	require.Nil(t, last.InstalledAt)
	require.Nil(t, last.InstalledBy)
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
}

// pin_on_chain: true for the pinned row or the anchor, false before the
// anchor, for another hash or a row that does not recompute.
// PinStillOnChain takes the anchor branch only at the genesis.
func TestPinOnChain(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	for range 3 {
		require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
	}
	head, err := guard.Head(ctx, a.Conn)
	require.NoError(t, err)
	on := func(h guard.ChainHead) bool {
		t.Helper()
		ok, err := guard.PinOnChain(ctx, a.Conn, h)
		require.NoError(t, err)
		return ok
	}
	still := func(h guard.ChainHead) bool {
		t.Helper()
		ok, err := guard.PinStillOnChain(ctx, a.Conn, h)
		require.NoError(t, err)
		return ok
	}
	require.True(t, on(head))
	require.True(t, still(head))
	require.True(t, on(guard.Genesis()))
	require.True(t, still(guard.Genesis()), "the genesis anchor counts")
	require.False(t, on(guard.ChainHead{Seq: head.Seq, Hash: bytes.Repeat([]byte{1}, 32)}))
	require.False(t, on(guard.ChainHead{Seq: head.Seq + 1, Hash: head.Hash}))

	var earlier guard.ChainHead
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT seq, hash FROM basalt_meta.ledger WHERE seq = $1`, head.Seq-1).
		Scan(&earlier.Seq, &earlier.Hash))
	require.True(t, still(earlier))

	// Retention moves the anchor to the head: a pin at the anchor is on the
	// chain but not still on it; one before is not on it.
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '2 years')`)
	require.True(t, on(head), "the anchor branch")
	require.False(t, still(head), "a pin at a later anchor: the history before it was cut")
	require.False(t, on(earlier))
	require.False(t, on(guard.Genesis()))
	next, err := guard.Head(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, still(next), "a pinned row after the anchor")

	// A row that holds the pinned hash but does not recompute to it.
	var forged []byte
	require.NoError(t, d.Admin.QueryRow(ctx, `UPDATE basalt_meta.ledger SET hash = sha256(hash) WHERE seq = $1 RETURNING hash`,
		next.Seq).Scan(&forged))
	require.False(t, on(guard.ChainHead{Seq: next.Seq, Hash: forged}))
}
