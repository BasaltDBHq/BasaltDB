package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// withdrawApprovals is the caller's guard holding one plugin approval; a
// withdraw of a pending one marks it WITHDRAWN, as the guard does.
type withdrawApprovals struct {
	PluginApprovalStore
	r     *guardmodel.PluginApprovalRecord
	calls *int
}

func (s withdrawApprovals) ReadPluginApproval(_ context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	if id != s.r.ApprovalID {
		return guardmodel.PluginApprovalRecord{}, false, nil
	}
	return *s.r, true, nil
}

func (s withdrawApprovals) WithdrawPluginApproval(_ context.Context, _ uuid.UUID, reason string) (*time.Time, error) {
	*s.calls++
	if s.r.Status != guardmodel.PluginApprovalStatusPending {
		return s.notWaiting(), nil
	}
	at := time.Now()
	s.r.Status, s.r.WithdrawnAt, s.r.WithdrawReason = guardmodel.PluginApprovalStatusWithdrawn, &at, reason
	return &at, nil
}

func withdrawRecord(binding string) *guardmodel.PluginApprovalRecord {
	return &guardmodel.PluginApprovalRecord{
		ApprovalID: uuid.MustParse(casePluginApproval), Name: "local-ner", Instance: "default",
		Status: guardmodel.PluginApprovalStatusPending, ExpiresAt: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), BindingText: binding,
	}
}

// The agent that opened a plugin approval withdraws it; one that is only
// named in it finds none, and nothing is withdrawn.
func TestWithdrawPluginApproval(t *testing.T) {
	t.Parallel()
	calls := 0
	r := withdrawRecord("{}")
	s := pluginService(t, &fakePluginRequests{}, withApprovals(withdrawApprovals{r: r, calls: &calls}))
	w, found, err := s.WithdrawPluginApproval(context.Background(), r.ApprovalID, "wrong plugin")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, action.Withdrawal{
		Kind: action.WithdrawPluginApproval, ID: r.ApprovalID, Status: "WITHDRAWN", WithdrawnAt: r.WithdrawnAt, Reason: "wrong plugin",
		Name: "local-ner", Instance: "default",
	}, w)
	require.Equal(t, 1, calls)

	calls = 0
	named := withdrawRecord("")
	s = pluginService(t, &fakePluginRequests{}, withApprovals(withdrawApprovals{r: named, calls: &calls}))
	_, found, err = s.WithdrawPluginApproval(context.Background(), named.ApprovalID, "wrong plugin")
	require.NoError(t, err)
	require.False(t, found, "only the opener reads the binding text and withdraws it")
	require.Zero(t, calls)
}

// The wait form reports a plugin approval the agent withdrew as WITHDRAWN,
// with its reason, not as ENDED.
func TestRequestPluginWaitReportsWithdrawn(t *testing.T) {
	t.Parallel()
	calls := 0
	r := withdrawRecord("{}")
	r.Status, r.WithdrawReason = guardmodel.PluginApprovalStatusWithdrawn, "wrong plugin"
	ended := PluginApprovalState{Name: "local-ner", Instance: "default", Agents: []string{"bot"}, State: PluginStateEnded}
	s := pluginService(t, &fakePluginRequests{states: []PluginApprovalState{ended}}, withApprovals(withdrawApprovals{r: r, calls: &calls}))
	out, err := callPlugin(t, s, map[string]any{"approvalId": casePluginApproval, "waitForApproval": 5}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStateWithdrawn, out.State)
	require.Equal(t, "The agent withdrew this request: wrong plugin. Nothing changed.", out.PersonMessage)
}

// notWaiting is the guard's answer for a request no longer waiting: no time.
func (withdrawApprovals) notWaiting() *time.Time { return nil }
