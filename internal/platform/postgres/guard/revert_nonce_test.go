package guard_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// The requesting role reads its revert's nonce (version 22); another
// agent's revert and an unknown id read alike, and no role outside the
// agents group may call the function.
func TestRevertNonceForTheRequestingRoleOnly(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()

	got, err := guard.RevertNonce(ctx, e.bot.Conn, e.prep.RevertID)
	require.NoError(t, err)
	require.Equal(t, nonceOf(t, e.d, e.prep.RevertID), got)

	e.widen(t, e.every())
	got, err = guard.RevertNonce(ctx, e.bot.Conn, e.prep.RevertID)
	require.NoError(t, err)
	require.Equal(t, nonceOf(t, e.d, e.prep.RevertID), got, "the nonce of the next widen, after a widen too")

	_, other := guard.RevertNonce(ctx, e.helper.Conn, e.prep.RevertID)
	requireRevertInvalid(t, other, "no such revert")
	_, unknown := guard.RevertNonce(ctx, e.bot.Conn, uuid.Must(uuid.NewV7()))
	requireRevertInvalid(t, unknown, "no such revert")
	require.Equal(t, scopeErrorText(t, other, e.prep.RevertID), scopeErrorText(t, unknown), "another agent's revert reads like an unknown one")

	require.False(t, scalarOf[bool](t, e.d.Admin,
		`SELECT has_function_privilege('public', 'basalt_meta.revert_nonce(uuid)', 'EXECUTE')`), "not executable by PUBLIC")
	require.Equal(t, guard.LatestVersion(), scalarOf[int](t, e.d.Admin, `SELECT max(version) FROM basalt_meta.schema_version`))
}
