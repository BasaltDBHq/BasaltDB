package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// fakePlugins reports problems per agent, as the engine's reporter does:
// only the entries that list the agent asked about.
type fakePlugins map[string][]PluginProblem

func (f fakePlugins) PluginProblems(agent string) []PluginProblem { return f[agent] }

func pluginStatus(t *testing.T, operatedBy, configPath string, foreground bool, r PluginReporter) StatusReport {
	t.Helper()
	d := deps()
	d.OperatedBy = operatedBy
	d.Plugins = r
	d.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", configPath, "linux")
	require.NoError(t, err)
	if foreground {
		cmds = cmds.Foreground()
	}
	d.Commands = cmds
	rep, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return rep
}

func samplePluginProblem(code string) fakePlugins {
	return fakePlugins{
		"bot":   {{Code: code, Name: "acme-ner", Instance: "client_x", Message: "plugin acme-ner/client_x is not ready (EXITED)", EngineKept: true}},
		"other": {{Code: code, Name: "acme-ner", Instance: "default", Message: "plugin acme-ner/default is not ready", EngineKept: true}},
	}
}

// requireRequestPlugin checks st calls request_plugin for acme-ner/client_x.
func requireRequestPlugin(t *testing.T, st toolresult.NextStep, remove bool) {
	t.Helper()
	require.Equal(t, "AGENT", st.Actor)
	require.Equal(t, "CALL_TOOL", st.Action)
	require.Equal(t, toolRequestPlugin, st.Tool)
	want := map[string]any{"name": "acme-ner", "instance": "client_x"}
	if remove {
		want["remove"] = true
	}
	require.Equal(t, want, st.Arguments)
}

// PLUGIN_UNAVAILABLE and PLUGIN_NOT_TRUSTED ask the person whether to
// remove the plugin, then remove it through request_plugin; no command.
// They are ERRORs: the agent is not ready.
func TestStatusShowsRemoveSteps(t *testing.T) {
	t.Parallel()
	for _, code := range []string{ProblemPluginUnavailable, ProblemPluginNotTrusted} {
		r := pluginStatus(t, "", "/srv/basalt/engine.json", true, samplePluginProblem(code))
		p := findProblem(t, r, code)
		require.False(t, r.Ready)
		require.Equal(t, "ERROR", p.Severity)
		require.Equal(t, "plugin acme-ner/client_x is not ready (EXITED)", p.Message)
		require.Len(t, p.NextSteps, 2)
		require.Equal(t, "ASK_PERSON", p.NextSteps[0].Action)
		requireRequestPlugin(t, p.NextSteps[1], true)
		require.NotContains(t, p.PersonMessage, "basalt ")
		require.NotContains(t, p.PersonMessage+p.Message, "acme-ner/default", "another agent's entry is not shown")
	}
}

// An entry withheld for an approval reason gets the contract's steps,
// the same on both personas: the agent opens a new approval with
// request_plugin; personMessage names no command.
func TestStatusShowsApprovalSteps(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		code    string
		actions []string
	}{
		{ProblemPluginAwaitingApproval, []string{"OPEN_LINK", "CALL_TOOL"}},
		{ProblemPluginApprovalExpired, []string{"ASK_PERSON", "CALL_TOOL"}},
		{ProblemPluginApprovalMismatch, []string{"ASK_PERSON", "CALL_TOOL"}},
	} {
		for _, operatedBy := range []string{"", "AGENT"} {
			r := pluginStatus(t, operatedBy, "/srv/basalt/engine.json", true, samplePluginProblem(c.code))
			p := findProblem(t, r, c.code)
			require.False(t, r.Ready, "an ERROR problem")
			require.Len(t, p.NextSteps, len(c.actions), c.code)
			for i, st := range p.NextSteps {
				require.Equal(t, c.actions[i], st.Action, c.code)
				require.Empty(t, st.Command, c.code)
			}
			requireRequestPlugin(t, p.NextSteps[1], false)
			require.Contains(t, p.PersonMessage, "acme-ner/client_x")
			require.NotContains(t, p.PersonMessage, "acme-ner/default", "another agent's entry is not shown")
			require.NotContains(t, p.PersonMessage, "basalt ")
		}
	}
}

// engine.json that the running engine cannot read is a WARNING naming no
// entry: the person fixes the edit.
func TestStatusShowsConfigInvalid(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{"", "AGENT"} {
		r := pluginStatus(t, operatedBy, "/srv/basalt/engine.json", true, fakePlugins{"bot": {{Code: ProblemPluginConfigInvalid, Message: "engine.json changed"}}})
		p := findProblem(t, r, ProblemPluginConfigInvalid)
		require.Equal(t, "WARNING", p.Severity)
		require.Equal(t, "engine.json changed", p.Message)
		require.Len(t, p.NextSteps, 1)
		require.Equal(t, "ASK_PERSON", p.NextSteps[0].Action)
		require.Contains(t, p.PersonMessage, "keeps running as before")
		require.NotContains(t, p.PersonMessage, "basalt ")
	}
}

func TestNoPluginProblemWithoutOne(t *testing.T) {
	t.Parallel()
	for name, rep := range map[string]PluginReporter{
		"no reporter":         nil,
		"another agent's one": fakePlugins{"other": {{Code: ProblemPluginUnavailable, Name: "acme-ner", Instance: "default", Message: "m"}}},
	} {
		r := pluginStatus(t, "", "", true, rep)
		for _, p := range r.Problems {
			require.NotContains(t, []string{ProblemPluginUnavailable, ProblemPluginNotTrusted}, p.Code, name)
		}
	}
}

type listedPlugins struct {
	fakePlugins
	entries []PluginEntry
}

func (l listedPlugins) PluginEntries(string) []PluginEntry { return l.entries }
