package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// The times the guard records for what the person did (approved_at,
// signed_at, applied_at, rejected_at) are read from the wall clock, the
// clock the deadlines are checked against, not the transaction's start.
// Each test opens a transaction, lets the clock move past its now(), and
// checks the recorded time is later than that now().

// lateTx is frozenTx with the clock moved past the transaction's now(); it
// returns the transaction and its now().
func lateTx(t *testing.T, c *pgx.Conn) (pgx.Tx, time.Time) {
	t.Helper()
	tx := frozenTx(t, c)
	var start time.Time
	// Plain SQL: the transaction's start, then a short wait inside it.
	require.NoError(t, tx.QueryRow(context.Background(), `SELECT now() FROM pg_sleep(0.05)`).Scan(&start))
	return tx, start
}

// recordedTimes are a revert's recorded times.
type recordedTimes struct {
	Signed, ApplyBy, Applied, Rejected *time.Time
}

// revertTimes reads a revert's recorded times as the admin.
func revertTimes(t *testing.T, d *guardtest.DB, id uuid.UUID) recordedTimes {
	t.Helper()
	var r recordedTimes
	// Plain SQL: test read of one row.
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT signed_at, apply_by, applied_at, rejected_at
		FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&r.Signed, &r.ApplyBy, &r.Applied, &r.Rejected))
	return r
}

func TestRecordedTimesReadTheWallClock(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)

	t.Run("submit_approval", func(t *testing.T) {
		ctx := context.Background()
		held, _ := previewAndHold(t, a.Conn, newRun(t, a, "approve late"), `DELETE FROM public.leads WHERE id = 70`, nil, []string{})
		tx, start := lateTx(t, a.Conn)
		at, err := guard.SubmitApproval(ctx, tx, held.ApprovalID, sign(t, p, held, nil))
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.True(t, at.After(start), "approved_at %s, transaction start %s", at, start)
	})

	t.Run("apply_revert", func(t *testing.T) {
		ctx := context.Background()
		in := newRun(t, a, "One lead")
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 140`))
		prep, as := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
		tx, start := lateTx(t, a.Conn)
		_, err := guard.ApplyRevert(ctx, tx, prep.RevertID, as)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		applied := revertTimes(t, d, prep.RevertID).Applied
		require.NotNil(t, applied)
		require.True(t, applied.After(start), "applied_at %s, transaction start %s", applied, start)
	})

	t.Run("reject_revert", func(t *testing.T) {
		ctx := context.Background()
		in := newRun(t, a, "Another lead")
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 141`))
		prep, _ := prepareSigned(t, a, p, revert.ScopeRun, in.RunID)
		tx, start := lateTx(t, a.Conn)
		out, err := guard.RejectRevert(ctx, tx, prep.RevertID, "", nil)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		rejected := revertTimes(t, d, prep.RevertID).Rejected
		require.NotNil(t, rejected)
		require.True(t, rejected.After(start), "rejected_at %s, transaction start %s", rejected, start)
		require.True(t, out.RejectedAt.Equal(*rejected))
	})
}

// A batched revert: the signature starts the 24-hour window at signed_at,
// and the last batch records applied_at, both from the wall clock.
func TestBatchedRevertTimesReadTheWallClock(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	prep, as := prepareSigned(t, e.a, e.p, revert.ScopeRun, e.in.RunID)

	tx, start := lateTx(t, e.a.Conn)
	_, err := guard.ApplyRevert(ctx, tx, prep.RevertID, as)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	times := revertTimes(t, e.d, prep.RevertID)
	signed, applyBy := times.Signed, times.ApplyBy
	require.NotNil(t, signed)
	require.True(t, signed.After(start), "signed_at %s, transaction start %s", signed, start)
	require.Equal(t, signed.Add(24*time.Hour), *applyBy)

	for {
		lines := pendingLines(t, e.a.Conn, prep.RevertID, revert.MaxBatch)
		if len(lines) == 0 {
			break
		}
		tx, start = lateTx(t, e.a.Conn)
		_, err := guard.ApplyRevertBatch(ctx, tx, prep.RevertID, lines)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}
	applied := revertTimes(t, e.d, prep.RevertID).Applied
	require.NotNil(t, applied)
	require.True(t, applied.After(start), "applied_at %s, last batch's transaction start %s", applied, start)
}
