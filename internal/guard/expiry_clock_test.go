package guard_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// The tests in this file hold one agent transaction open across an expiry:
// the transaction starts (fixing now()), the person's deadline passes on the
// wall clock, and only then does the transaction submit, apply or commit.
// Expiry is read from the wall clock, so each is refused, as it is on a
// fresh connection.

// frozenTx begins a transaction on c, so now() inside it is fixed from here.
// It is rolled back at cleanup unless the test ends it.
func frozenTx(t *testing.T, c *pgx.Conn) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := c.Begin(ctx)
	require.NoError(t, err)
	// Plain SQL: the first statement, so the transaction has started.
	_, err = tx.Exec(ctx, `SELECT now()`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

// expireNow sets column (expires_at or apply_by) of row id in table to the
// wall clock as the admin, after the frozen transaction started: past for
// the wall clock from here on, still ahead of that transaction's now().
func expireNow(t *testing.T, d *guardtest.DB, table, column string, id uuid.UUID) {
	t.Helper()
	key := map[string]string{"approvals": "approval_id", "reverts": "revert_id"}[table]
	require.NotEmpty(t, key)
	// Plain SQL: test fixture on fixed table and column names.
	d.Exec(t, `UPDATE basalt_meta.`+table+` SET `+column+` = clock_timestamp() WHERE `+key+` = $1`, id)
}

func TestApprovalExpiryReadsTheWallClock(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "expiry on the wall clock")

	t.Run("submit_approval", func(t *testing.T) {
		ctx := context.Background()
		held, _ := previewAndHold(t, a.Conn, in, `DELETE FROM public.leads WHERE id = 62`, nil, []string{})
		tx := frozenTx(t, a.Conn)
		expireNow(t, d, "approvals", "expires_at", held.ApprovalID)
		_, err := guard.SubmitApproval(ctx, tx, held.ApprovalID, sign(t, p, held, nil))
		requireCode(t, err, guard.CodeApprovalExpired)
	})

	t.Run("the check when the approved write starts", func(t *testing.T) {
		ctx := context.Background()
		const stmt = `DELETE FROM public.leads WHERE id = 63`
		held, _ := previewAndHold(t, a.Conn, in, stmt, nil, []string{})
		_, err := guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
		require.NoError(t, err)
		tx := frozenTx(t, a.Conn)
		expireNow(t, d, "approvals", "expires_at", held.ApprovalID)
		require.NoError(t, guard.BeginApproved(ctx, tx, in, held.ApprovalID))
		_, err = tx.Exec(ctx, stmt)
		requireCode(t, err, guard.CodeApprovalExpired)
	})

	t.Run("the check at commit", func(t *testing.T) {
		ctx := context.Background()
		const stmt = `DELETE FROM public.leads WHERE id = 64`
		held, _ := previewAndHold(t, a.Conn, in, stmt, nil, []string{})
		_, err := guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
		require.NoError(t, err)
		tx := frozenTx(t, a.Conn)
		require.NoError(t, guard.BeginApproved(ctx, tx, in, held.ApprovalID))
		_, err = tx.Exec(ctx, stmt)
		require.NoError(t, err)
		_, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "DELETE", Statement: stmt})
		require.NoError(t, err)
		expireNow(t, d, "approvals", "expires_at", held.ApprovalID)
		requireCode(t, tx.Commit(ctx), guard.CodeApprovalExpired)
		require.Equal(t, 1, count(t, d.Admin, `SELECT count(id)::int FROM public.leads WHERE id = 64`))
	})
}

func TestRevertExpiryReadsTheWallClock(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)

	t.Run("apply_revert", func(t *testing.T) {
		ctx := context.Background()
		in := newRun(t, a, "One lead")
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 130`))
		prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
		tx := frozenTx(t, a.Conn)
		expireNow(t, d, "reverts", "expires_at", prep.RevertID)
		_, err := guard.ApplyRevert(ctx, tx, prep.RevertID, as)
		requireCode(t, err, guard.CodeRevertExpired)
	})

	t.Run("reject_revert", func(t *testing.T) {
		ctx := context.Background()
		in := newRun(t, a, "Another lead")
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 131`))
		prep, _ := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
		tx := frozenTx(t, a.Conn)
		expireNow(t, d, "reverts", "expires_at", prep.RevertID)
		_, err := guard.RejectRevert(ctx, tx, prep.RevertID, "", nil)
		requireCode(t, err, guard.CodeRevertExpired)
	})
}

func TestRevertBatchDeadlineReadsTheWallClock(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	prep, _ := e.prepareAndSign(t)

	tx := frozenTx(t, e.a.Conn)
	expireNow(t, e.d, "reverts", "apply_by", prep.RevertID)
	_, err := guard.ApplyRevertBatch(ctx, tx, prep.RevertID, []int{1})
	requireCode(t, err, guard.CodeRevertExpired)
}
