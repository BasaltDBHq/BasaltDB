package agent

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// gatedService is a service on an outdated guard whose approval and revert
// stores panic when called: a page or CLI call that reached them would
// relay a signature to a guard this build calls unsafe.
func gatedService(t *testing.T) *Service {
	t.Helper()
	d := deps()
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOutdated, []int{guard.LatestVersion()}, nil)}
	setApprovals(&d, struct{ approvalStore }{})
	setReverts(&d, struct{ Reverts }{})
	return NewService(d)
}

func requireGuardOutdated(t *testing.T, err error, path string) {
	t.Helper()
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te, path)
	require.Equal(t, CodeUnavailable, te.Code, path)
	require.Equal(t, reasonGuardOutdated, te.Reason, path)
}

func TestPagesRelayNothingOnAnOutdatedGuard(t *testing.T) {
	t.Parallel()
	s, ctx, id := gatedService(t), context.Background(), uuid.New()

	_, err := s.RelayApproval(ctx, approval.Response{ApprovalID: id})
	requireGuardOutdated(t, err, "pages approve")
	_, err = s.ApprovalRequest(ctx, id)
	requireGuardOutdated(t, err, "approval page")
	_, _, err = s.RelayRevert(ctx, revert.Response{RevertID: id})
	requireGuardOutdated(t, err, "pages revert")
	_, err = s.RevertRequest(ctx, id, "secret")
	requireGuardOutdated(t, err, "revert page")
	_, err = s.RescopeRevert(ctx, id, "secret", ScopeRequest{})
	requireGuardOutdated(t, err, "pages scope")

	// The page tells the person the agent gives them a link to update it.
	_, err = s.RelayApproval(ctx, approval.Response{ApprovalID: id})
	pf := s.PageFailure(err)
	require.Contains(t, pf.PersonMessage, "The agent gives you a link")
	require.NotContains(t, pf.PersonMessage, "basalt ", "the person runs no command")
}
