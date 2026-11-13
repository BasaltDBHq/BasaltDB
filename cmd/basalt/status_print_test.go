package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
)

// A step the person message already names is printed once: NO_PASSKEY's
// message ends "Run: <command>", so no second Run line follows it.
func TestStatusPrintsEachCommandOnce(t *testing.T) {
	t.Parallel()
	const cmd = "basalt init --agent bot --add-passkey"
	var b strings.Builder
	writeStatus(&b, statusOut{StatusReport: agent.StatusReport{Agent: "bot", Problems: []agent.Problem{
		{
			Code: "NO_PASSKEY", Severity: "WARNING", Message: "no passkey", PersonMessage: "No passkey is registered. Run: " + cmd,
			NextSteps: []agent.NextStep{{Command: cmd}},
		},
		{
			Code: "GUARD_OUTDATED", Severity: "ERROR", Message: "old guard", PersonMessage: "The guard is old.",
			NextSteps: []agent.NextStep{{Command: "basalt upgrade --agent bot"}},
		},
	}}})
	out := b.String()
	require.Equal(t, 1, strings.Count(out, cmd), out)
	require.Contains(t, out, "Run: basalt upgrade --agent bot", "a step the message does not name is printed")
}
