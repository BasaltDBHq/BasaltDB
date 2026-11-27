package revert

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// withdrawStore holds one revert; a withdraw of a pending one marks it
// WITHDRAWN with the reason, as the guard does.
type withdrawStore struct {
	Store
	r     *action.Revert
	calls *int
}

func (s withdrawStore) FindRevert(_ context.Context, id uuid.UUID) (action.Revert, error) {
	if s.r == nil || id != s.r.ID {
		return action.Revert{}, &revertstore.RevertRefusalError{Reason: revertstore.RevertNotFound}
	}
	return *s.r, nil
}

func (s withdrawStore) WithdrawRevert(_ context.Context, _ uuid.UUID, reason string) (*time.Time, error) {
	*s.calls++
	if s.r.Status != action.RevertPending {
		return s.notWaiting(), nil
	}
	at := time.Now()
	s.r.Status, s.r.WithdrawnAt, s.r.WithdrawReason = action.RevertWithdrawn, &at, reason
	return &at, nil
}

// The agent withdraws its own pending revert; one that no longer waits
// keeps its status; another agent's revert, or none, is not found.
func TestWithdrawRevert(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ status, want string }{
		{action.RevertPending, action.RevertWithdrawn},
		{action.RevertApplied, action.RevertApplied},
		{action.RevertRejected, action.RevertRejected},
	} {
		r := caseRevert(false)
		r.Status, r.ExpiresAt = c.status, time.Now().Add(time.Hour)
		calls := 0
		rc := newService(t, "linux", "", withStore(withdrawStore{r: &r, calls: &calls}))
		w, found, err := rc.WithdrawRevert(context.Background(), r.ID, "the person changed their mind")
		require.NoError(t, err, c.status)
		require.True(t, found, c.status)
		require.Equal(t, c.want, w.Status, c.status)
		require.Equal(t, action.WithdrawRevert, w.Kind)
		require.Equal(t, 1, calls)
	}
	calls := 0
	rc := newService(t, "linux", "", withStore(withdrawStore{calls: &calls}))
	_, found, err := rc.WithdrawRevert(context.Background(), uuid.Must(uuid.NewV7()), "x")
	require.NoError(t, err)
	require.False(t, found)
	require.Zero(t, calls)
}

// The wait form of request_revert reports a withdrawn revert as WITHDRAWN
// at once, with the agent's reason, never as still waiting.
func TestAwaitRevertReportsWithdrawn(t *testing.T) {
	t.Parallel()
	r := caseRevert(false)
	r.Status, r.WithdrawReason, r.ExpiresAt = action.RevertWithdrawn, "the person changed their mind", time.Now().Add(time.Hour)
	calls := 0
	rc := newService(t, "linux", "", withStore(withdrawStore{r: &r, calls: &calls}))
	out, err := rc.AwaitRevert(context.Background(), AwaitRevertParams{RevertID: r.ID, Wait: 5 * time.Second})
	require.NoError(t, err)
	require.Equal(t, action.RevertWithdrawn, out.Revert.Status)
	require.Equal(t, "The agent withdrew this request: the person changed their mind. Nothing changed.", out.PersonMessage)
	require.Len(t, out.NextSteps, 1)
	require.Equal(t, toolresult.ActionStop, out.NextSteps[0].Action)
}

// notWaiting is the guard's answer for a request no longer waiting: no time.
func (withdrawStore) notWaiting() *time.Time { return nil }
