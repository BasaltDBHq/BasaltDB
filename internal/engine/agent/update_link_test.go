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

// On an engine the setup page removed, every fix finishes the removal: the
// agent runs basalt init once, which removes the engine service.
func TestRemovedEngineStepsFinishTheRemoval(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "darwin")
	require.NoError(t, err)
	gone := false
	removed := cmds.UpdateLink(testUpdateLink).Removed(func() bool { return gone })
	for _, reason := range []string{reasonCredentialRejected, reasonGuardMissing, reasonGuardOutdated} {
		b := NewSteps()
		person := fixSteps(b, removed, reason)
		require.NotContains(t, person, "Last step", "not removed yet: the usual fix")

		gone = true
		b = NewSteps()
		person = fixSteps(b, removed, reason)
		steps := actions(t, b)
		require.True(t, hasStep(steps, mcp.ActorAgent, mcp.ActionRunCommand, "basalt init --agent bot"), "%s: %+v", reason, steps)
		require.True(t, hasStep(steps, mcp.ActorAgent, mcp.ActionStop, ""), reason)
		require.False(t, hasStep(steps, mcp.ActorPerson, mcp.ActionOpenLink, ""), "no update link on a removed engine")
		require.Contains(t, person, "Last step: the agent runs basalt init once")
		gone = false
	}
}
