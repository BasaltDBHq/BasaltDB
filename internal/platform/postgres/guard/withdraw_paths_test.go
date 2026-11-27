package guard_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// _commit_approval, the write's commit check, refuses a held write the
// agent withdrew. No write reaches it through the engine (_check_approval
// refuses first, and a withdrawn approval is never signed), so it is
// called on the held change itself; without its WITHDRAWN check it would
// answer that the approval is not signed.
func TestCommitApprovalRefusesWithdrawn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "remove a lead")
	held, _ := previewAndHold(t, a.Conn, in, heldDelete, []any{3}, []string{})
	_, err := withdraw(a.Conn, "withdraw_approval", held.ApprovalID, withdrawReason)
	require.NoError(t, err)

	_, err = d.Admin.Exec(ctx, `SELECT basalt_meta._commit_approval(c) FROM basalt_meta.changes c WHERE c.approval_id = $1`, held.ApprovalID)
	requireWithdrawn(t, err, guard.CodeApprovalInvalid)
	require.Nil(t, scalarOf[*uuid.UUID](t, d.Admin,
		`SELECT used_by_change FROM basalt_meta.approvals WHERE approval_id = $1`, held.ApprovalID), "the approval is not used")
}

// open_reveal (through _reveal_approval_lock) refuses the person's valid
// reveal proof for a held write the agent withdrew, and appends nothing.
func TestOpenRevealRefusesWithdrawn(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	as, key := e.proof(t, "the page's reveal secret")
	_, err := withdraw(e.a.Conn, "withdraw_approval", e.held.ApprovalID, withdrawReason)
	require.NoError(t, err)

	_, err = guard.OpenReveal(context.Background(), e.a.Conn, e.held.ApprovalID, as, key)
	requireWithdrawn(t, err, guard.CodeApprovalInvalid)
	require.Empty(t, ledgerDetails(t, e.d, "ROWS_REVEALED"))
}

// reveal_approval_rows refuses a ticket opened before the agent withdrew
// the held write: no row comes back.
func TestRevealApprovalRowsRefusesWithdrawn(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	ticket := e.open(t)
	_, err := e.reveal(t, ticket, rerun{})
	require.NoError(t, err, "the ticket works before the withdrawal")
	_, err = withdraw(e.a.Conn, "withdraw_approval", e.held.ApprovalID, withdrawReason)
	require.NoError(t, err)

	rows, err := e.reveal(t, ticket, rerun{})
	require.Nil(t, rows)
	requireWithdrawn(t, err, guard.CodeApprovalInvalid)
}

// reveal_revert_rows refuses the person's valid reveal proof for a revert
// the agent withdrew: no row comes back, and the nonce is not used.
func TestRevealRevertRowsRefusesWithdrawn(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	id := e.prep.RevertID
	as, key := e.proof(t, id, "secret")
	_, err := withdraw(e.a.Conn, "withdraw_revert", id, withdrawReason)
	require.NoError(t, err)
	nonce := revertRevealNonce(t, e.d, id)

	_, err = guard.RevealRevertRows(context.Background(), e.a.Conn, id, as, key)
	requireWithdrawn(t, err, guard.CodeRevertInvalid)
	require.Equal(t, nonce, revertRevealNonce(t, e.d, id))
	require.Empty(t, ledgerDetails(t, e.d, "ROWS_REVEALED"))
}

// requireChangesStatusValid is the change status check as version 15
// leaves it: present and validated.
func requireChangesStatusValid(t *testing.T, d *guardtest.DB) {
	t.Helper()
	require.True(t, scalarOf[bool](t, d.Admin, `SELECT convalidated FROM pg_catalog.pg_constraint
		WHERE conrelid = 'basalt_meta.changes'::regclass AND conname = 'changes_status'`))
}

// pendingOfEachKind is a held write, a revert and a plugin approval of
// agent a, each still waiting for the person.
type pendingOfEachKind struct {
	approval, revert, plugin uuid.UUID
}

func openOneOfEachKind(t *testing.T, a *guardtest.Agent, lead int) pendingOfEachKind {
	t.Helper()
	ctx := context.Background()
	in := newRun(t, a, "work to undo")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, fmt.Sprintf(`UPDATE public.leads SET status = 'won' WHERE id = %d`, lead)))
	prep, err := guard.PrepareRevert(ctx, a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo it")
	require.NoError(t, err)
	held, _ := previewAndHold(t, a.Conn, newRun(t, a, "remove a lead"), heldDelete, []any{lead + 1}, []string{})
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)
	return pendingOfEachKind{approval: held.ApprovalID, revert: prep.RevertID, plugin: opened.ID}
}

func (p pendingOfEachKind) requireStatus(t *testing.T, a *guardtest.Agent, want string) {
	t.Helper()
	require.Equal(t, want, scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_approvals WHERE approval_id = $1`, p.approval), "held write")
	require.Equal(t, want, scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, p.revert), "revert")
	require.Equal(t, want, approvalStatus(t, a.Conn, p.plugin), "plugin approval")
}

func (p pendingOfEachKind) withdrawAll(t *testing.T, a *guardtest.Agent) {
	t.Helper()
	for fn, id := range map[string]uuid.UUID{
		"withdraw_approval": p.approval, "withdraw_revert": p.revert, "withdraw_plugin_approval": p.plugin,
	} {
		at, err := withdraw(a.Conn, fn, id, withdrawReason)
		require.NoError(t, err, fn)
		require.NotNil(t, at, fn)
	}
}

// Version 15's SQL runs again over a guard already at it, holding a
// withdrawn and a waiting request of each kind: nothing changes, the
// change status check stays validated, and the waiting ones can still be
// withdrawn.
func TestWithdrawMigrationRunsAgain(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	require.GreaterOrEqual(t, scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`), guard.WithdrawVersion)
	done := openOneOfEachKind(t, a, 10)
	done.withdrawAll(t, a)
	waiting := openOneOfEachKind(t, a, 20)
	versions := count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.schema_version`)

	sql := guard.WithdrawSQL(d.Names)
	for range 2 {
		d.Exec(t, "BEGIN; SET LOCAL ROLE "+d.Names.Guard()+"; SET LOCAL search_path = pg_catalog, pg_temp;"+sql+"COMMIT;")
	}
	require.Equal(t, versions, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.schema_version`))
	requireChangesStatusValid(t, d)
	done.requireStatus(t, a, "WITHDRAWN")
	require.Equal(t, "APPROVAL_WITHDRAWN", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_changes WHERE approval_id = $1`, done.approval))
	waiting.requireStatus(t, a, "PENDING")
	waiting.withdrawAll(t, a)
	waiting.requireStatus(t, a, "WITHDRAWN")
	require.Nil(t, guardVerify(t, d))
}

// A guard at version 14 holding a waiting held write, revert and plugin
// approval is updated to version 15 in place: all three still wait, and
// the agent can withdraw each.
func TestUpdateToWithdrawKeepsWaitingRequests(t *testing.T) {
	restore := guardtest.UpToVersion(t, guard.WithdrawVersion-1)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	require.Equal(t, guard.WithdrawVersion-1, scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
	waiting := openOneOfEachKind(t, a, 30)
	held := scalarOf[uuid.UUID](t, d.Admin, `SELECT held_change FROM basalt_meta.approvals WHERE approval_id = $1`, waiting.approval)

	restore()
	a = d.NewAgent(t, "bot", leads, leads) // basalt init over it: the update
	require.Equal(t, guard.LatestVersion(), scalarOf[int](t, d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
	requireChangesStatusValid(t, d)
	waiting.requireStatus(t, a, "PENDING")
	require.Equal(t, "APPROVAL_PENDING", scalarOf[string](t, d.Admin,
		`SELECT status FROM basalt_meta.changes WHERE change_id = $1`, held))

	waiting.withdrawAll(t, a)
	waiting.requireStatus(t, a, "WITHDRAWN")
	require.Equal(t, "APPROVAL_WITHDRAWN", scalarOf[string](t, d.Admin,
		`SELECT status FROM basalt_meta.changes WHERE change_id = $1`, held))
	require.Nil(t, guardVerify(t, d))
}
