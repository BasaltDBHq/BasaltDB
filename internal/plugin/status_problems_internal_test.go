package plugin

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// statusProblems is the status's problem list for problems of one agent, on
// an engine operated by operatedBy: foreground engines name their own
// restart commands.
func statusProblems(t *testing.T, operatedBy, configPath string, foreground bool, problems []pluginProblem) (list []guidance.Problem, ready bool) {
	t.Helper()
	cmds := guidance.NewCommands("bot", configPath, config.DefaultPath("linux"), "linux",
		osservice.Manager())
	if foreground {
		cmds = cmds.Foreground()
	}
	ps := guidance.Problems{Cmds: cmds.OperatedBy(operatedBy)}
	addPluginProblems(&ps, problems)
	list, err := ps.Sorted()
	require.NoError(t, err)
	ready = true
	for _, p := range list {
		if p.Severity == mcpcontract.SeverityError {
			ready = false
		}
	}
	return list, ready
}

func problemOf(t *testing.T, list []guidance.Problem, code string) guidance.Problem {
	t.Helper()
	for _, p := range list {
		if p.Code == code {
			return p
		}
	}
	require.Failf(t, "problem missing", "no %s in %+v", code, list)
	return guidance.Problem{}
}

func sampleProblem(code string) []pluginProblem {
	return []pluginProblem{{Code: code, Name: "acme-ner", Instance: "client_x", Message: "plugin acme-ner/client_x is not ready (EXITED)", EngineKept: true}}
}

// requireRequestPlugin checks st calls request_plugin for acme-ner/client_x.
func requireRequestPlugin(t *testing.T, st toolresult.NextStep, remove bool) {
	t.Helper()
	require.Equal(t, "AGENT", st.Actor)
	require.Equal(t, "CALL_TOOL", st.Action)
	require.Equal(t, guidance.ToolRequestPlugin, st.Tool)
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
	for _, code := range []string{problemPluginUnavailable, problemPluginNotTrusted} {
		list, ready := statusProblems(t, "", "/srv/basalt/engine.json", true, sampleProblem(code))
		p := problemOf(t, list, code)
		require.False(t, ready)
		require.Equal(t, "ERROR", p.Severity)
		require.Equal(t, "plugin acme-ner/client_x is not ready (EXITED)", p.Message)
		require.Len(t, p.NextSteps, 2)
		require.Equal(t, "ASK_PERSON", p.NextSteps[0].Action)
		requireRequestPlugin(t, p.NextSteps[1], true)
		require.NotContains(t, p.PersonMessage, "basalt ")
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
		{problemPluginAwaitingApproval, []string{"OPEN_LINK", "CALL_TOOL"}},
		{problemPluginApprovalExpired, []string{"ASK_PERSON", "CALL_TOOL"}},
		{problemPluginApprovalWithdrawn, []string{"ASK_PERSON", "CALL_TOOL"}},
		{problemPluginApprovalMismatch, []string{"ASK_PERSON", "CALL_TOOL"}},
	} {
		for _, operatedBy := range []string{"", "AGENT"} {
			list, ready := statusProblems(t, operatedBy, "/srv/basalt/engine.json", true, sampleProblem(c.code))
			p := problemOf(t, list, c.code)
			require.False(t, ready, "an ERROR problem")
			require.Len(t, p.NextSteps, len(c.actions), c.code)
			for i, st := range p.NextSteps {
				require.Equal(t, c.actions[i], st.Action, c.code)
				require.Empty(t, st.Command, c.code)
			}
			requireRequestPlugin(t, p.NextSteps[1], false)
			require.Contains(t, p.PersonMessage, "acme-ner/client_x")
			require.NotContains(t, p.PersonMessage, "basalt ")
		}
	}
}

// engine.json that the running engine cannot read is a WARNING naming no
// entry: the person fixes the edit.
func TestStatusShowsConfigInvalid(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{"", "AGENT"} {
		list, _ := statusProblems(t, operatedBy, "/srv/basalt/engine.json", true, []pluginProblem{{Code: problemPluginConfigInvalid, Message: "engine.json changed"}})
		p := problemOf(t, list, problemPluginConfigInvalid)
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
	list, ready := statusProblems(t, "", "", true, nil)
	require.Empty(t, list)
	require.True(t, ready)
}

func TestConfigEntryStepsOnlyAskThePerson(t *testing.T) {
	t.Parallel()
	for _, code := range []string{problemPluginUnavailable, problemPluginNotTrusted, problemPluginAwaitingApproval, problemPluginApprovalExpired, problemPluginApprovalWithdrawn, problemPluginApprovalMismatch} {
		for _, operatedBy := range []string{"", "AGENT"} {
			conf := []pluginProblem{{Code: code, Name: "acme-ner", Instance: "client_x", Message: "m"}}
			list, _ := statusProblems(t, operatedBy, "", false, conf)
			p := problemOf(t, list, code)
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
			list, _ := statusProblems(t, operatedBy, "", true, []pluginProblem{{
				Code: problemPluginNoticesDropped, Name: "acme-notify", Instance: "client_x", EngineKept: kept,
				Message: "plugin acme-notify/client_x did not get 3 approval notices of this agent in the last 24 hours",
			}})
			p := problemOf(t, list, problemPluginNoticesDropped)
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
		nameless := []pluginProblem{{Code: problemPluginUnavailable, Message: "no engine-kept plugin is served: " + file + " is bad", File: file}}
		list, _ := statusProblems(t, operatedBy, "", false, nameless)
		p := problemOf(t, list, problemPluginUnavailable)
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

// status.plugins lists the agent's entries, READY unless a plugin problem
// names the entry; dropped notices do not make an entry NOT_READY.
func TestPluginHealth(t *testing.T) {
	t.Parallel()
	entries := []pluginEntry{{Name: "acme-ner", Instance: "client_x"}, {Name: "acme-ner", Instance: "default"}, {Name: "acme-notify", Instance: "client_x"}}
	probs := append(sampleProblem(problemPluginUnavailable), pluginProblem{Code: problemPluginNoticesDropped, Name: "acme-notify", Instance: "client_x"})
	require.Equal(t, []guidance.PluginHealth{
		{Name: "acme-ner", Instance: "client_x", Health: pluginHealthNotReady, Problem: problemPluginUnavailable},
		{Name: "acme-ner", Instance: "default", Health: pluginHealthReady},
		{Name: "acme-notify", Instance: "client_x", Health: pluginHealthReady},
	}, pluginHealth(entries, probs))
	require.Nil(t, pluginHealth(nil, probs), "no entries: nothing to show")
}

// Each plugin problem of the status catalog is built with the steps the
// catalog prescribes, on both personas; the agent's status tests cover the
// rest of the catalog and require these codes beside their own.
func TestEveryPluginProblemObeysTheCatalog(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		foreground bool
		problems   []pluginProblem
	}{
		problemPluginUnavailable: {false, sampleProblem(problemPluginUnavailable)},
		problemPluginNotTrusted:  {false, sampleProblem(problemPluginNotTrusted)},
		// Plugin approvals are same-user mode: a foreground engine.
		problemPluginAwaitingApproval:  {true, sampleProblem(problemPluginAwaitingApproval)},
		problemPluginApprovalExpired:   {true, sampleProblem(problemPluginApprovalExpired)},
		problemPluginApprovalWithdrawn: {true, sampleProblem(problemPluginApprovalWithdrawn)},
		problemPluginApprovalMismatch:  {true, sampleProblem(problemPluginApprovalMismatch)},
		problemPluginConfigInvalid:     {true, []pluginProblem{{Code: problemPluginConfigInvalid, Message: "engine.json changed and the engine cannot read its plugins"}}},
		problemPluginNoticesDropped:    {true, sampleProblem(problemPluginNoticesDropped)},
	}
	keys := make([]string, 0, len(cases))
	for code := range cases {
		keys = append(keys, code)
	}
	slices.Sort(keys)
	require.Equal(t, stepcatalogtest.PluginProblemCodes(), keys)
	for _, operatedBy := range []string{mcpcontract.OperatedByPerson, mcpcontract.OperatedByAgent} {
		for code, c := range cases {
			t.Run(operatedBy+"/"+code, func(t *testing.T) {
				t.Parallel()
				list, ready := statusProblems(t, operatedBy, "", c.foreground, c.problems)
				stepcatalogtest.RequireProblemObeysCatalog(t, list, ready, code, operatedBy)
			})
		}
	}
}
