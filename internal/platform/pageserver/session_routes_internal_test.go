package pageserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The loopback mux mounts the session's route table, so both serve the
// same API routes: these patterns, and no other.
func TestSessionRoutePatterns(t *testing.T) {
	t.Parallel()
	got := make([]string, 0, len(sessionRoutes))
	for _, r := range sessionRoutes {
		got = append(got, r.pattern())
	}
	require.ElementsMatch(t, []string{
		"GET /api/v1/approvals/{approvalId}",
		"POST /api/v1/approvals/{approvalId}/approve",
		"GET /api/v1/reverts/{revertId}",
		"POST /api/v1/reverts/{revertId}/apply",
		"POST /api/v1/reverts/{revertId}/scope",
		"POST /api/v1/reverts/{revertId}/reject",
		"POST /api/v1/approvals/{approvalId}/reveal",
		"POST /api/v1/reverts/{revertId}/reveal",
		"GET /api/v1/plugins/{approvalId}",
		"POST /api/v1/plugins/{approvalId}/approve",
	}, got)
}
