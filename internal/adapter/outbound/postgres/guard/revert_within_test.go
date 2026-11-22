package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
)

// PrepareRevertWithin replaces the role's statement timeout for the
// prepare only: a limit lower than the agent's own still applies, the
// session keeps its own afterwards, and a prepare cut short stores nothing.
func TestPrepareRevertWithin(t *testing.T) {
	t.Parallel()
	e := newBulkEnv(t)
	ctx := context.Background()
	own := scalarOf[string](t, e.a.Conn, `SHOW statement_timeout`)

	_, err := guard.PrepareRevertWithin(ctx, e.a.Conn, e.scope(), "Undo", 0)
	require.ErrorIs(t, err, guard.ErrPrepareTimeout, "0 would mean no limit")

	_, err = guard.PrepareRevertWithin(ctx, e.a.Conn, e.scope(), "Undo", time.Millisecond)
	require.Equal(t, "57014", guardtest.SQLState(err), "the trial of %d rows takes longer than 1 ms", bulkRows)
	require.Zero(t, scalarOf[int](t, e.a.Conn, `SELECT count(revert_id)::int FROM basalt_meta.agent_reverts`), "nothing stored")
	require.Equal(t, own, scalarOf[string](t, e.a.Conn, `SHOW statement_timeout`), "the session keeps its own timeout")

	prep, err := guard.PrepareRevertWithin(ctx, e.a.Conn, e.scope(), "Undo", guard.CLIPrepareTimeout)
	require.NoError(t, err)
	require.True(t, prep.Batched)
	require.Equal(t, 1, scalarOf[int](t, e.a.Conn, `SELECT count(revert_id)::int FROM basalt_meta.agent_reverts`))
}
