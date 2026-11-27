package approval

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
)

// withdrawStore holds one held write; a withdraw of a pending one marks it
// WITHDRAWN with the reason, as the guard does.
type withdrawStore struct {
	catalogStore
	a     *action.Approval
	calls *int
}

func (s withdrawStore) FindApproval(_ context.Context, id uuid.UUID) (action.Approval, error) {
	if s.a == nil || id != s.a.ID {
		return action.Approval{}, &approvalstore.ApprovalRefusalError{Reason: approvalstore.ApprovalNotFound}
	}
	return *s.a, nil
}

func (s withdrawStore) WithdrawApproval(_ context.Context, _ uuid.UUID, reason string) (*time.Time, error) {
	*s.calls++
	if s.a.Status != action.ApprovalPending {
		return s.notWaiting(), nil
	}
	at := time.Now()
	s.a.Status, s.a.WithdrawnAt, s.a.WithdrawReason = action.ApprovalWithdrawn, &at, reason
	return &at, nil
}

func TestWithdrawApproval(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	for _, c := range []struct {
		name, status, want string
		calls              int
	}{
		{"pending", action.ApprovalPending, action.ApprovalWithdrawn, 1},
		{"withdrawn already", action.ApprovalWithdrawn, action.ApprovalWithdrawn, 1},
		{"signed", action.ApprovalApproved, action.ApprovalApproved, 1},
		{"applied", action.ApprovalApplied, action.ApprovalApplied, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := &action.Approval{ID: id, Status: c.status, ExpiresAt: time.Now().Add(time.Hour)}
			calls := 0
			ac := newService(t, "linux", "", func(s *settings) { s.store = withdrawStore{a: a, calls: &calls} })
			w, found, err := ac.WithdrawApproval(context.Background(), id, "the person changed their mind")
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, c.calls, calls)
			require.Equal(t, action.WithdrawHeldWrite, w.Kind)
			require.Equal(t, c.want, w.Status)
		})
	}
}

// An id the agent holds no held write for is not found, and nothing is
// withdrawn: the caller tries a plugin approval next.
func TestWithdrawApprovalOfAnotherAgent(t *testing.T) {
	t.Parallel()
	calls := 0
	ac := newService(t, "linux", "", func(s *settings) { s.store = withdrawStore{calls: &calls} })
	_, found, err := ac.WithdrawApproval(context.Background(), uuid.Must(uuid.NewV7()), "x")
	require.NoError(t, err)
	require.False(t, found)
	require.Zero(t, calls)
}

// A pending held write past its deadline, which the guard leaves as it
// is, reads EXPIRED.
func TestWithdrawApprovalPastItsDeadline(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &action.Approval{ID: id, Status: action.ApprovalPending, ExpiresAt: time.Now().Add(-time.Hour)}
	calls := 0
	ac := newService(t, "linux", "", func(s *settings) { s.store = expiredStore{withdrawStore{a: a, calls: &calls}} })
	w, found, err := ac.WithdrawApproval(context.Background(), id, "x")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, action.ApprovalExpired, w.Status)
}

// expiredStore withdraws nothing: the guard found the held write expired.
type expiredStore struct{ withdrawStore }

func (s expiredStore) WithdrawApproval(context.Context, uuid.UUID, string) (*time.Time, error) {
	*s.calls++
	return s.notWaiting(), nil
}

// notWaiting is the guard's answer for a request no longer waiting: no time.
func (withdrawStore) notWaiting() *time.Time { return nil }
