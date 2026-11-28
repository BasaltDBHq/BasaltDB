package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

const testUpdateLink = "http://localhost:8787/setup/#1.eyJqb2IiOiJVUERBVEUifQ"

func actions(t *testing.T, b *guidance.Steps) []toolresult.NextStep {
	t.Helper()
	steps, err := b.Build()
	require.NoError(t, err)
	return steps
}

// upgradeWarningSteps are the steps of the guard-upgrade warning run_start gives an agent whose commands are cmds.
func upgradeWarningSteps(t *testing.T, cmds guidance.Commands) []toolresult.NextStep {
	t.Helper()
	d := deps()
	d.Core.Commands = cmds
	d.Status.Upgrade = fakeUpgrade{available: true}
	warnings := NewService(d).status.UpgradeWarnings(context.Background())
	require.Len(t, warnings, 1)
	return warnings[0].NextSteps
}

func hasStep(steps []toolresult.NextStep, actor, action, value string) bool {
	for _, s := range steps {
		if s.Actor == actor && s.Action == action && (value == "" || s.URL == value || s.Command == value) {
			return true
		}
	}
	return false
}

func TestGuardStepsHandThePersonTheUpdateLink(t *testing.T) {
	t.Parallel()
	cmds, err := newCommands("bot", "", "darwin", osservice.Manager())
	require.NoError(t, err)
	with := cmds.UpdateLink(testUpdateLink)

	b := guidance.NewSteps()
	person := guidance.FixSteps(b, with, guidance.ReasonGuardOutdated)
	steps := actions(t, b)
	require.True(t, hasStep(steps, toolresult.ActorPerson, toolresult.ActionOpenLink, testUpdateLink), "%+v", steps)
	require.False(t, hasStep(steps, toolresult.ActorAgent, toolresult.ActionRunCommand, ""), "no basalt init when the link is there")
	require.Contains(t, person, "Open the link the agent gives you")

	steps = upgradeWarningSteps(t, with)
	require.True(t, hasStep(steps, toolresult.ActorPerson, toolresult.ActionOpenLink, testUpdateLink), "%+v", steps)

	// Without the link, and for any other fix, the agent runs basalt init.
	for _, tc := range []struct {
		cmds   guidance.Commands
		reason string
	}{{cmds, guidance.ReasonGuardOutdated}, {with, guidance.ReasonCredentialRejected}, {with, guidance.ReasonGuardMissing}} {
		b = guidance.NewSteps()
		guidance.FixSteps(b, tc.cmds, tc.reason)
		steps = actions(t, b)
		require.True(t, hasStep(steps, toolresult.ActorAgent, toolresult.ActionRunCommand, "basalt init --agent bot"), "%s: %+v", tc.reason, steps)
		require.False(t, hasStep(steps, toolresult.ActorPerson, toolresult.ActionOpenLink, ""), tc.reason)
	}
	require.True(t, hasStep(upgradeWarningSteps(t, cmds), toolresult.ActorAgent, toolresult.ActionRunCommand, "basalt init --agent bot"))
}

// On an engine the setup page removed, every fix is the same: the agent
// runs basalt init once, whose page asks the person to set BasaltDB up
// again or finish the removal.
func TestRemovedEngineStepsDropTheConnection(t *testing.T) {
	t.Parallel()
	cmds, err := newCommands("bot", "", "darwin", osservice.Manager())
	require.NoError(t, err)
	gone := false
	removed := cmds.UpdateLink(testUpdateLink).Removed(func() bool { return gone })
	for _, reason := range []string{guidance.ReasonCredentialRejected, guidance.ReasonGuardMissing, guidance.ReasonGuardOutdated} {
		b := guidance.NewSteps()
		person := guidance.FixSteps(b, removed, reason)
		require.NotContains(t, person, "set BasaltDB up again", "not removed yet: the usual fix")

		gone = true
		b = guidance.NewSteps()
		person = guidance.FixSteps(b, removed, reason)
		steps := actions(t, b)
		require.Len(t, steps, 1, "%s: %+v", reason, steps)
		require.True(t, hasStep(steps, toolresult.ActorAgent, toolresult.ActionStop, ""), reason)
		require.False(t, hasStep(steps, toolresult.ActorPerson, toolresult.ActionOpenLink, ""), "no update link on a removed engine")
		require.Contains(t, person, "Your agent drops its connection to it now")
		gone = false
	}
}
