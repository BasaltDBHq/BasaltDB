package guard_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// rejectedRow is what the agent role reads of its revert in agent_reverts.
type rejectedRow struct {
	Status     string
	RejectedAt *time.Time
	Note       *string
}

func agentRevertRow(t *testing.T, e widenEnv, revertID uuid.UUID) rejectedRow {
	t.Helper()
	var r rejectedRow
	require.NoError(t, e.bot.Conn.QueryRow(context.Background(),
		`SELECT status, rejected_at, reject_note FROM basalt_meta.agent_reverts WHERE revert_id = $1`, revertID).
		Scan(&r.Status, &r.RejectedAt, &r.Note))
	return r
}

// Before a widen the agent role rejects its own revert with no token: the
// path is LINK_OR_AGENT. The revert is REJECTED with the note, and can no
// longer be signed, rescoped, reset or rejected again.
func TestRejectRevertBeforeWiden(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	sig, err := e.p.Sign(passkeytest.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)

	out, err := guard.RejectRevert(ctx, e.bot.Conn, id, "not this one, I fixed it by hand", nil)
	require.NoError(t, err)
	require.Equal(t, id, out.RevertID)
	require.Equal(t, "REJECTED", out.Status)
	require.WithinDuration(t, time.Now(), out.RejectedAt, time.Minute)

	row := agentRevertRow(t, e, id)
	require.Equal(t, "REJECTED", row.Status)
	require.NotNil(t, row.RejectedAt)
	require.True(t, out.RejectedAt.Equal(*row.RejectedAt))
	require.Equal(t, "not this one, I fixed it by hand", *row.Note)

	details := ledgerDetails(t, e.d, "REVERT_REJECTED")
	require.Len(t, details, 1)
	require.Equal(t, map[string]any{
		"revertId": id.String(), "note": "not this one, I fixed it by hand",
		"via": guardmodel.RejectViaLinkOrAgent,
	}, details[0])

	_, err = guard.ApplyRevert(ctx, e.bot.Conn, id, sig)
	requireRevertInvalid(t, err, "rejected")
	require.Equal(t, "a", leadStatus(t, e.d, 30), "nothing was reverted")
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, revertstore.RescopeRequest{RevertID: id, Select: e.own()})
	requireRevertInvalid(t, err, "rejected")
	_, err = guard.ResetRevert(ctx, e.bot.Conn, id)
	requireRevertInvalid(t, err, "rejected")
	_, err = guard.RejectRevert(ctx, e.bot.Conn, id, "", nil)
	requireRevertInvalid(t, err, "rejected")
	require.Len(t, ledgerDetails(t, e.d, "REVERT_REJECTED"), 1)
	require.Nil(t, guardVerify(t, e.d))
}

// Once the person widened the revert, a reject needs its scope token: the
// agent role calling reject_revert itself, without it or with a wrong one,
// is refused with the one widen answer and nothing changes. With the token
// the path is SCOPE_TOKEN, and the token is never recorded.
func TestRejectRevertAfterWidenNeedsTheToken(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	widened := e.widen(t, e.every())
	token := []byte(widened.ScopeToken)
	before := storedRevert(t, e.d, id)

	var text string
	for name, tok := range map[string][]byte{
		"no token":     nil,
		"a zero token": make([]byte, 16),
		"a short one":  token[:8],
	} {
		_, err := guard.RejectRevert(ctx, e.bot.Conn, id, "stop", tok)
		got := requireWidenRefused(t, err)
		if text == "" {
			text = got
		}
		require.Equal(t, text, got, name)
	}
	require.Equal(t, before, storedRevert(t, e.d, id), "nothing changed")
	require.Equal(t, "PENDING", agentRevertRow(t, e, id).Status)
	require.Empty(t, ledgerDetails(t, e.d, "REVERT_REJECTED"))

	// Narrowed back to the agent's own work under the token: still widened
	// once (a ceiling), so the token is still required.
	_, err := guard.RescopeRevert(ctx, e.bot.Conn, revertstore.RescopeRequest{RevertID: id, Select: e.own(), Token: token})
	require.NoError(t, err)
	_, err = guard.RejectRevert(ctx, e.bot.Conn, id, "", nil)
	requireWidenRefused(t, err)

	out, err := guard.RejectRevert(ctx, e.bot.Conn, id, "", token)
	require.NoError(t, err)
	require.Equal(t, "REJECTED", out.Status)
	row := agentRevertRow(t, e, id)
	require.Equal(t, "REJECTED", row.Status)
	require.Nil(t, row.Note, "no note")
	details := ledgerDetails(t, e.d, "REVERT_REJECTED")
	require.Len(t, details, 1)
	require.Equal(t, map[string]any{"revertId": id.String(), "via": guardmodel.RejectViaScopeToken}, details[0])
	raw := scalarOf[string](t, e.d.Admin, `SELECT detail::text FROM basalt_meta.ledger WHERE kind = 'REVERT_REJECTED'`)
	require.NotContains(t, raw, widened.ScopeToken.String(), "the token is never recorded")
	require.Nil(t, guardVerify(t, e.d))
}

// Only a PENDING, unsigned, unexpired revert of the caller's own can be
// rejected; another role's revert reads exactly like an unknown id; a token
// on a revert never widened is refused; the note is at most 500
// characters; and no role outside the agents group may call the function.
func TestRejectRevertRefusals(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()

	theirs, err := guard.PrepareRevert(ctx, e.helper.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: e.help.RunID}, "x")
	require.NoError(t, err)
	unknown := uuid.Must(uuid.NewV7())
	_, errTheirs := guard.RejectRevert(ctx, e.bot.Conn, theirs.RevertID, "", nil)
	_, errUnknown := guard.RejectRevert(ctx, e.bot.Conn, unknown, "", nil)
	requireRevertRefused(t, errUnknown, guard.RevertNotFound, "no such revert")
	require.Equal(t, scopeErrorText(t, errUnknown, unknown), scopeErrorText(t, errTheirs, theirs.RevertID))
	require.Equal(t, "PENDING", scalarOf[string](t, e.d.Admin,
		`SELECT CASE WHEN rejected_at IS NULL THEN 'PENDING' ELSE 'REJECTED' END FROM basalt_meta.reverts WHERE revert_id = $1`, theirs.RevertID))

	_, err = guard.RejectRevert(ctx, e.bot.Conn, e.prep.RevertID, "", make([]byte, 16))
	requireWidenRefused(t, err)

	_, err = guard.RejectRevert(ctx, e.bot.Conn, e.prep.RevertID, strings.Repeat("é", guardmodel.MaxRejectNote+1), nil)
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	_, err = guard.RejectRevert(ctx, e.bot.Conn, e.prep.RevertID, strings.Repeat("é", guardmodel.MaxRejectNote), nil)
	require.NoError(t, err, "500 characters, whatever their bytes")

	for name, sql := range map[string]string{
		"signed":  `UPDATE basalt_meta.reverts SET signed_at = now(), apply_by = now() + interval '1 day' WHERE revert_id = $1`,
		"expired": `UPDATE basalt_meta.reverts SET expires_at = now() - interval '1 second' WHERE revert_id = $1`,
		"applied": `UPDATE basalt_meta.reverts SET applied_at = now() WHERE revert_id = $1`,
	} {
		prep, err := guard.PrepareRevert(ctx, e.bot.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: e.botA.RunID}, name)
		require.NoError(t, err)
		e.d.Exec(t, sql, prep.RevertID)
		_, err = guard.RejectRevert(ctx, e.bot.Conn, prep.RevertID, "", nil)
		want := guard.CodeRevertInvalid
		if name == "expired" {
			want = guard.CodeRevertExpired
		}
		requireCode(t, err, want)
	}
	require.Len(t, ledgerDetails(t, e.d, "REVERT_REJECTED"), 1, "only the one accepted reject")

	require.False(t, scalarOf[bool](t, e.d.Admin,
		`SELECT has_function_privilege('public', 'basalt_meta.reject_revert(uuid, text, bytea)', 'EXECUTE')`), "not executable by PUBLIC")
}

// A widen does not make the reject the person's alone: the agent role can
// reset the revert (no token, owner Q8), which drops the ceiling, and then
// reject it with no token. The ledger shows exactly that: REVERT_RESET,
// then REVERT_REJECTED via LINK_OR_AGENT.
func TestRejectRevertAfterResetNeedsNoToken(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	e.widen(t, e.every())
	_, err := guard.RejectRevert(ctx, e.bot.Conn, id, "", nil)
	requireWidenRefused(t, err)

	_, err = guard.ResetRevert(ctx, e.bot.Conn, id)
	require.NoError(t, err)
	_, err = guard.RejectRevert(ctx, e.bot.Conn, id, "", nil)
	require.NoError(t, err)

	kinds := scalarOf[string](t, e.d.Admin, `SELECT string_agg(kind, ',' ORDER BY seq) FROM basalt_meta.ledger
		WHERE kind IN ('REVERT_RESCOPED', 'REVERT_RESET', 'REVERT_REJECTED')`)
	require.Equal(t, "REVERT_RESCOPED,REVERT_RESET,REVERT_REJECTED", kinds)
	details := ledgerDetails(t, e.d, "REVERT_REJECTED")
	require.Len(t, details, 1)
	require.Equal(t, guardmodel.RejectViaLinkOrAgent, details[0]["via"])
	require.Equal(t, "REJECTED", agentRevertRow(t, e, id).Status)
}
