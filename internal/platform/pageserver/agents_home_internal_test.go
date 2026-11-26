package pageserver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The home page reads each agent once per homeTTL: a page that reloads
// gets the kept answer.
func TestAgentsHomeKeepsItsAnswerForTheTTL(t *testing.T) {
	t.Parallel()
	reads := 0
	h := NewAgentsHome([]HomeAgent{{DBKey: "db", Provider: ProviderPostgres, Health: func(context.Context) (*guardmodel.Status, *int) {
		reads++
		n := 2
		return &guardmodel.Status{State: guardmodel.GuardOK}, &n
	}}})
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	first := h.Home(context.Background())
	require.Equal(t, HomeGuardCurrent, first.Guard)
	require.Equal(t, 2, *first.Passkeys)
	now = now.Add(homeTTL - time.Second)
	h.Home(context.Background())
	require.Equal(t, 1, reads)
	now = now.Add(2 * time.Second)
	h.Home(context.Background())
	require.Equal(t, 2, reads)
}
