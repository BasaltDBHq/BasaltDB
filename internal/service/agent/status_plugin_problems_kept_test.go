package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// A plugin in engine.json is not request_plugin's to change: its problems
// only ask the person, who edits the file.
func TestConfigEntryStepsOnlyAskThePerson(t *testing.T) {
	t.Parallel()
	for _, code := range []string{ProblemPluginUnavailable, ProblemPluginNotTrusted, ProblemPluginAwaitingApproval, ProblemPluginApprovalExpired, ProblemPluginApprovalMismatch} {
		for _, operatedBy := range []string{"", "AGENT"} {
			conf := fakePlugins{"bot": {{Code: code, Name: "acme-ner", Instance: "client_x", Message: "m"}}}
			p := findProblem(t, pluginStatus(t, operatedBy, "", false, conf), code)
			require.Len(t, p.NextSteps, 1, code)
			require.NotEqual(t, "CALL_TOOL", p.NextSteps[0].Action, code)
			require.Empty(t, p.NextSteps[0].Command, code)
			require.Contains(t, p.PersonMessage, "engine.json", code)
		}
	}
}

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
			require.Equal(t, "AGENT", p.NextSteps[0].Actor)
			require.Equal(t, "CALL_TOOL", p.NextSteps[0].Action)
			require.Equal(t, guidance.ToolListPending, p.NextSteps[0].Tool)
			require.Contains(t, p.PersonMessage, "ask the agent what waits for your approval")
		}
	}
}

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
