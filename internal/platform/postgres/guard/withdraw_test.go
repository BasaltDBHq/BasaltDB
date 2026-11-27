package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

const withdrawReason = "the person changed their mind"

// withdraw calls one of the guard's withdraw functions as the agent role
// would on its own connection: the time it withdrew the request, nil when
// the request no longer waited.
func withdraw(q guard.Querier, fn string, id uuid.UUID, reason string) (*time.Time, error) {
	var at *time.Time
	// Plain SQL: the guard function called as an agent could, by its name.
	err := q.QueryRow(context.Background(), `SELECT basalt_meta.`+fn+`($1::uuid, $2)`, id, reason).Scan(&at)
	return at, err
}

// requireWithdrawn is the refusal of a withdrawn request: the code, the
// typed detail WITHDRAWN and the reason in the hint.
func requireWithdrawn(t *testing.T, err error, code guard.Code) {
	t.Helper()
	requireCode(t, err, code)
	require.Contains(t, scopeErrorText(t, err), "|WITHDRAWN|the agent withdrew this request: "+withdrawReason+"; nothing changed")
}

// A held write the agent withdraws reads WITHDRAWN, its change record
// APPROVAL_WITHDRAWN, and the person's signature and the agent's write
// with it are both refused. A second withdraw changes nothing; another
// agent's approval reads like none.
func TestWithdrawHeldWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	other := d.NewAgent(t, "other", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "remove a lead")
	const stmt = `DELETE FROM public.leads WHERE id = $1`
	held, _ := previewAndHold(t, a.Conn, in, stmt, []any{3}, []string{})

	_, err := withdraw(other.Conn, "withdraw_approval", held.ApprovalID, withdrawReason)
	requireNoSuchApproval(t, err)
	_, err = withdraw(a.Conn, "withdraw_approval", held.ApprovalID, "")
	requireCode(t, err, guard.CodeLedgerInputInvalid)

	at, err := withdraw(a.Conn, "withdraw_approval", held.ApprovalID, withdrawReason)
	require.NoError(t, err)
	require.NotNil(t, at)
	require.Equal(t, "WITHDRAWN", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_approvals WHERE approval_id = $1`, held.ApprovalID))
	require.Equal(t, withdrawReason, scalarOf[string](t, a.Conn,
		`SELECT withdraw_reason FROM basalt_meta.agent_approvals WHERE approval_id = $1`, held.ApprovalID))
	require.Equal(t, "APPROVAL_WITHDRAWN", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_changes WHERE approval_id = $1`, held.ApprovalID))
	require.Equal(t, []map[string]any{{"approvalId": held.ApprovalID.String(), "reason": withdrawReason}},
		ledgerDetails(t, d, "APPROVAL_WITHDRAWN"))

	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	requireWithdrawn(t, err, guard.CodeApprovalInvalid)
	requireWithdrawn(t, applyApproved(ctx, a.Conn, in, held.ApprovalID, stmt, []any{3}), guard.CodeApprovalInvalid)

	again, err := withdraw(a.Conn, "withdraw_approval", held.ApprovalID, "twice")
	require.NoError(t, err)
	require.Nil(t, again, "an approval already withdrawn is left as it is")
	require.Len(t, ledgerDetails(t, d, "APPROVAL_WITHDRAWN"), 1)

	// A signed approval no longer waits: withdraw leaves it, and the write
	// it approves still applies.
	signed, _ := previewAndHold(t, a.Conn, in, `DELETE FROM public.leads WHERE id = $1`, []any{4}, []string{})
	_, err = guard.SubmitApproval(ctx, a.Conn, signed.ApprovalID, sign(t, p, signed, nil))
	require.NoError(t, err)
	at, err = withdraw(a.Conn, "withdraw_approval", signed.ApprovalID, withdrawReason)
	require.NoError(t, err)
	require.Nil(t, at)
	require.NoError(t, applyApproved(ctx, a.Conn, in, signed.ApprovalID, `DELETE FROM public.leads WHERE id = $1`, []any{4}))

	// The table refuses a row both withdrawn and signed, whoever writes it.
	_, err = d.Admin.Exec(ctx, `UPDATE basalt_meta.approvals SET approved_at = now() WHERE approval_id = $1`, held.ApprovalID)
	require.Error(t, err)
	require.Nil(t, guardVerify(t, d))
}

// A revert the agent withdraws reads WITHDRAWN; the person's signature, a
// rescope, a reset and a reject are refused, and nothing is reverted.
func TestWithdrawRevert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	other := d.NewAgent(t, "other", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "Mark leads won")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 90 AND 92`))
	prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)

	_, err := withdraw(other.Conn, "withdraw_revert", prep.RevertID, withdrawReason)
	requireRevertRefused(t, err, guard.RevertNotFound, "no such revert")

	at, err := withdraw(a.Conn, "withdraw_revert", prep.RevertID, withdrawReason)
	require.NoError(t, err)
	require.NotNil(t, at)
	require.Equal(t, "WITHDRAWN", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))
	require.Equal(t, []map[string]any{{"revertId": prep.RevertID.String(), "reason": withdrawReason}},
		ledgerDetails(t, d, "REVERT_WITHDRAWN"))

	_, err = guard.ApplyRevert(ctx, a.Conn, prep.RevertID, as)
	requireWithdrawn(t, err, guard.CodeRevertInvalid)
	require.Equal(t, "won", leadStatus(t, d, 90), "nothing was reverted")
	_, err = guard.RescopeRevert(ctx, a.Conn, revertstore.RescopeRequest{
		RevertID: prep.RevertID,
		Select:   revert.Select{Scope: revert.ScopeRun, ScopeID: in.RunID},
	})
	requireWithdrawn(t, err, guard.CodeRevertInvalid)
	_, err = guard.ResetRevert(ctx, a.Conn, prep.RevertID)
	requireWithdrawn(t, err, guard.CodeRevertInvalid)
	_, err = guard.RejectRevert(ctx, a.Conn, prep.RevertID, "", nil)
	requireWithdrawn(t, err, guard.CodeRevertInvalid)

	again, err := withdraw(a.Conn, "withdraw_revert", prep.RevertID, withdrawReason)
	require.NoError(t, err)
	require.Nil(t, again)

	// An applied revert no longer waits: withdraw leaves it.
	in2 := newRun(t, a, "Mark more leads won")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in2, `UPDATE public.leads SET status = 'won' WHERE id = 93`))
	applied := revertScope(t, a, p, revert.ScopeRun, in2.RunID)
	require.NotEqual(t, uuid.Nil, applied.ChangeID)
	id := scalarOf[uuid.UUID](t, a.Conn, `SELECT revert_id FROM basalt_meta.agent_reverts WHERE status = 'APPLIED'`)
	at, err = withdraw(a.Conn, "withdraw_revert", id, withdrawReason)
	require.NoError(t, err)
	require.Nil(t, at)
	require.Nil(t, guardVerify(t, d))
}

// A plugin approval its opener withdraws reads WITHDRAWN, and the
// person's signature is refused. An agent that did not open it, even one
// it names, gets NOT_FOUND, and only the opener sees the reason.
func TestWithdrawPluginApproval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", leads, nil)
	b := d.NewAgent(t, "product_b", leads, nil)
	p := person(t, d)
	opened, err := guard.OpenPluginApproval(ctx, a.Conn, localApproval(a.Name, b.Name), guardmodel.PluginSettings{})
	require.NoError(t, err)

	_, err = withdraw(b.Conn, "withdraw_plugin_approval", opened.ID, withdrawReason)
	requireGuardDetail(t, err, guard.CodeApprovalInvalid, guard.DetailApprovalNotFound)

	at, err := withdraw(a.Conn, "withdraw_plugin_approval", opened.ID, withdrawReason)
	require.NoError(t, err)
	require.NotNil(t, at)
	require.Equal(t, "WITHDRAWN", approvalStatus(t, a.Conn, opened.ID))
	require.Equal(t, withdrawReason, scalarOf[string](t, a.Conn,
		`SELECT withdraw_reason FROM basalt_meta.agent_plugin_approvals WHERE approval_id = $1`, opened.ID))
	require.Nil(t, scalarOf[*string](t, b.Conn,
		`SELECT withdraw_reason FROM basalt_meta.agent_plugin_approvals WHERE approval_id = $1`, opened.ID))
	require.Equal(t, 1, ledgerKinds(t, d, a.Role, "PLUGIN_APPROVAL_WITHDRAWN"))

	_, err = guard.SubmitPluginApproval(ctx, b.Conn, signPlugin(t, p, opened))
	requireWithdrawn(t, err, guard.CodeApprovalInvalid)
	require.Zero(t, ledgerKinds(t, d, a.Role, string(guardmodel.PluginApproved)))

	again, err := withdraw(a.Conn, "withdraw_plugin_approval", opened.ID, withdrawReason)
	require.NoError(t, err)
	require.Nil(t, again)
	require.Nil(t, guardVerify(t, d))
}
