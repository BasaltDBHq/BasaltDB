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
