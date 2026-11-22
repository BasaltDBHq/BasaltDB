package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

const testUpdateLink = "http://localhost:8787/setup/#1.eyJqb2IiOiJVUERBVEUifQ"

func actions(t *testing.T, b *Steps) []mcp.NextStep {
	t.Helper()
	steps, err := b.Build()
	require.NoError(t, err)
	return steps
}

func hasStep(steps []mcp.NextStep, actor, action, value string) bool {
	for _, s := range steps {
		if s.Actor == actor && s.Action == action && (value == "" || s.URL == value || s.Command == value) {
			return true
		}
	}
	return false
}

func TestGuardStepsHandThePersonTheUpdateLink(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "darwin")
	require.NoError(t, err)
	with := cmds.UpdateLink(testUpdateLink)

	b := NewSteps()
	person := fixSteps(b, with, reasonGuardOutdated)
	steps := actions(t, b)
	require.True(t, hasStep(steps, mcp.ActorPerson, mcp.ActionOpenLink, testUpdateLink), "%+v", steps)
	require.False(t, hasStep(steps, mcp.ActorAgent, mcp.ActionRunCommand, ""), "no basalt init when the link is there")
	require.Contains(t, person, "Open the link the agent gives you")

	b = NewSteps()
	upgradeSteps(b, with)
	steps = actions(t, b)
	require.True(t, hasStep(steps, mcp.ActorPerson, mcp.ActionOpenLink, testUpdateLink), "%+v", steps)

	// Without the link, and for any other fix, the agent runs basalt init.
	for _, tc := range []struct {
		cmds   Commands
		reason string
	}{{cmds, reasonGuardOutdated}, {with, reasonCredentialRejected}, {with, reasonGuardMissing}} {
		b = NewSteps()
		fixSteps(b, tc.cmds, tc.reason)
		steps = actions(t, b)
		require.True(t, hasStep(steps, mcp.ActorAgent, mcp.ActionRunCommand, "basalt init --agent bot"), "%s: %+v", tc.reason, steps)
		require.False(t, hasStep(steps, mcp.ActorPerson, mcp.ActionOpenLink, ""), tc.reason)
	}
	b = NewSteps()
	upgradeSteps(b, cmds)
	require.True(t, hasStep(actions(t, b), mcp.ActorAgent, mcp.ActionRunCommand, "basalt init --agent bot"))
}
