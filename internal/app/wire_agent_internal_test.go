package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A port AgentHostDeps leaves unset is an adapter the agent cannot reach: a
// nil function panics on first use, and a nil error value would turn the
// ledger's NOT_FOUND into an INTERNAL tool error. NewService names every
// required port that is missing; the ports the app wires must not be among
// them, whatever the test or the config supplies for the rest.
func TestAgentHostDepsFillsEveryAdapterPort(t *testing.T) {
	t.Parallel()
	var msg string
	func() {
		defer func() { msg, _ = recover().(string) }()
		NewService(AgentHostDeps())
	}()
	require.NotEmpty(t, msg, "an empty Deps must be refused")
	supplied := []string{
		"Core.Errors.InvalidParams", "Core.Errors.InvalidIntent", "Core.Errors.RowTooLarge", "Core.ServiceManager",
		"Agent.Record", "Approval.ErrNotFound", "Revert.AfterAnswer", "Revert.RotateSession",
		"Delivery.VaultConflict", "Delivery.ErrVaultNotConnected", "Status.CrashReports",
		"Status.LatestGuardVersion", "Status.UpdateMessage", "Status.StartHoldOffUntil",
	}
	for _, name := range supplied {
		require.NotContains(t, strings.Split(strings.TrimPrefix(msg, "agent: required dependencies missing: "), ", "), name, "AgentHostDeps leaves %s unset", name)
	}
	require.NotZero(t, AgentHostDeps().Approval.SortSpec, "AgentHostDeps leaves Approval.SortSpec unset")
	require.NotZero(t, AgentHostDeps().Plugin.ApprovalsVersion, "AgentHostDeps leaves Plugin.ApprovalsVersion unset")
}
