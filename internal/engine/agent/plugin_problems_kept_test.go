package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// An entry the engine keeps itself is turned off without sudo (sudo is
// refused for it) and basalt plugin check does not find it: its steps hold
// neither, whatever it is withheld for.
func TestEngineKeptEntryStepsHaveNoSudoAndNoCheck(t *testing.T) {
	t.Parallel()
	for _, code := range []string{ProblemPluginUnavailable, ProblemPluginNotTrusted, ProblemPluginAwaitingApproval, ProblemPluginApprovalExpired, ProblemPluginApprovalMismatch} {
		for _, operatedBy := range []string{"", "AGENT"} {
			kept := fakePlugins{"bot": {{Code: code, Name: "acme-ner", Instance: "client_x", Message: "m", EngineKept: true}}}
			p := findProblem(t, pluginStatus(t, operatedBy, "", false, kept), code)
			require.NotEmpty(t, p.NextSteps, code)
			for _, st := range p.NextSteps {
				require.NotContains(t, st.Command, "sudo", code)
				require.NotContains(t, st.Command, "plugin check", code)
			}
			require.NotContains(t, p.PersonMessage, "sudo", code)
			require.NotContains(t, p.PersonMessage, "plugin check", code)
		}
	}
	// A config entry keeps both on a service engine.
	conf := fakePlugins{"bot": {{Code: ProblemPluginUnavailable, Name: "acme-ner", Instance: "default", Message: "m"}}}
	p := findProblem(t, pluginStatus(t, "", "", false, conf), ProblemPluginUnavailable)
	require.Equal(t, "basalt plugin check acme-ner", p.NextSteps[0].Command)
	require.Equal(t, "sudo basalt plugin disable acme-ner", p.NextSteps[1].Command)
}

// Dropped approval notices are a WARNING with one step: basalt plugin check
// for the entry, or basalt plugin list for one the engine keeps itself,
// which check does not find. The message says nothing was lost.
func TestStatusShowsDroppedNotices(t *testing.T) {
	t.Parallel()
	for _, kept := range []bool{false, true} {
		for _, operatedBy := range []string{"", "AGENT"} {
			r := pluginStatus(t, operatedBy, "", true, fakePlugins{"bot": {{
				Code: ProblemPluginNoticesDropped, Name: "acme-notify", Instance: "client_x", EngineKept: kept,
				Message: "plugin acme-notify/client_x did not get 3 approval notices of this agent in the last 24 hours",
			}}})
			p := findProblem(t, r, ProblemPluginNoticesDropped)
			require.Equal(t, "WARNING", p.Severity)
			require.Len(t, p.NextSteps, 1)
			require.Equal(t, "PERSON", p.NextSteps[0].Actor)
			require.Equal(t, "RUN_COMMAND", p.NextSteps[0].Action)
			want := "basalt plugin check acme-notify --instance client_x"
			if kept {
				want = "basalt plugin list"
			}
			require.Equal(t, want, p.NextSteps[0].Command)
			require.NotContains(t, p.NextSteps[0].Command, "sudo")
			require.Contains(t, p.PersonMessage, "ask the agent what waits for your approval")
			require.Contains(t, p.PersonMessage, want)
		}
	}
}

// A problem that names no entry (the engine's entries file is unusable)
// never gives a command with an empty plugin name: its steps move the file
// aside and restart the engine, the person's, on an agent-operated engine
// too.
func TestNamelessPluginProblemHasItsOwnSteps(t *testing.T) {
	t.Parallel()
	const file = "/var/lib/basalt/plugins.json"
	for _, operatedBy := range []string{"", "AGENT"} {
		nameless := fakePlugins{"bot": {{Code: ProblemPluginUnavailable, Message: "no engine-kept plugin is served: " + file + " is bad", File: file}}}
		p := findProblem(t, pluginStatus(t, operatedBy, "", false, nameless), ProblemPluginUnavailable)
		require.Len(t, p.NextSteps, 2)
		require.Equal(t, "sudo mv "+file+" "+file+".bad", p.NextSteps[0].Command)
		require.Equal(t, "sudo systemctl restart basalt-engine.service", p.NextSteps[1].Command)
		for _, st := range p.NextSteps {
			require.Equal(t, "PERSON", st.Actor)
			require.Equal(t, "RUN_COMMAND", st.Action)
			require.NotContains(t, st.Command, "plugin check")
		}
		require.NotContains(t, p.PersonMessage, "plugin check")
		require.NotContains(t, p.PersonMessage, "plugin disable")
	}
}
