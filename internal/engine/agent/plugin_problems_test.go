package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
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
	d.Probe = &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", configPath, "linux", nil)
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
		"bot":   {{Code: code, Name: "acme-ner", Instance: "client_x", Message: "plugin acme-ner/client_x is not ready (EXITED)"}},
		"other": {{Code: code, Name: "acme-ner", Instance: "default", Message: "plugin acme-ner/default is not ready"}},
	}
}

// PLUGIN_UNAVAILABLE gives the person two steps: basalt plugin check and
// basalt plugin disable for the entry, with --instance and --config when
// they are not the defaults, and sudo for disable on a service engine. It
// is an ERROR: the agent is not ready.
func TestStatusShowsTwoPersonSteps(t *testing.T) {
	t.Parallel()
	for _, code := range []string{ProblemPluginUnavailable, ProblemPluginNotTrusted} {
		r := pluginStatus(t, "", "/srv/basalt/engine.json", true, samplePluginProblem(code))
		p := findProblem(t, r, code)
		require.False(t, r.Ready)
		require.Equal(t, "ERROR", p.Severity)
		require.Equal(t, "plugin acme-ner/client_x is not ready (EXITED)", p.Message)
		require.Len(t, p.NextSteps, 2)
		for _, st := range p.NextSteps {
			require.Equal(t, "PERSON", st.Actor)
			require.Equal(t, "RUN_COMMAND", st.Action)
		}
		require.Equal(t, "basalt plugin check acme-ner --instance client_x --config /srv/basalt/engine.json", p.NextSteps[0].Command)
		require.Equal(t, "basalt plugin disable acme-ner --instance client_x --config /srv/basalt/engine.json", p.NextSteps[1].Command)
		require.Contains(t, p.PersonMessage, p.NextSteps[0].Command)
		require.NotContains(t, p.PersonMessage+p.Message, "acme-ner/default", "another agent's entry is not shown")
	}

	r := pluginStatus(t, "", "", false, fakePlugins{"bot": {{Code: ProblemPluginUnavailable, Name: "acme-ner", Instance: "default", Message: "plugin acme-ner/default is not ready"}}})
	p := findProblem(t, r, ProblemPluginUnavailable)
	require.Equal(t, "basalt plugin check acme-ner", p.NextSteps[0].Command)
	require.Equal(t, "sudo basalt plugin disable acme-ner", p.NextSteps[1].Command)
}

// No reporter, or no problem for this agent: no plugin problem.
// An entry withheld for an approval reason gets the contract's steps: the
// commands are the person's on a person-operated engine and the agent's on
// an agent-operated one, where personMessage names no command.
func TestStatusShowsApprovalSteps(t *testing.T) {
	t.Parallel()
	const enable = "basalt plugin enable acme-ner --instance client_x --approve-with-passkey --json --config /srv/basalt/engine.json"
	for _, c := range []struct {
		code    string
		actions []string
		cmds    []string
	}{
		{
			// No restart: the engine starts the plugin once it is signed.
			ProblemPluginAwaitingApproval,
			[]string{"OPEN_LINK", "RUN_COMMAND"},
			[]string{"", enable},
		},
		{
			ProblemPluginApprovalExpired,
			[]string{"RUN_COMMAND", "RUN_COMMAND"},
			[]string{enable, "basalt plugin remove acme-ner --instance client_x --config /srv/basalt/engine.json"},
		},
		{
			ProblemPluginApprovalMismatch,
			[]string{"ASK_PERSON", "RUN_COMMAND", "RUN_COMMAND"},
			[]string{"", enable, "basalt plugin disable acme-ner --instance client_x --config /srv/basalt/engine.json"},
		},
	} {
		for _, operatedBy := range []string{"", "AGENT"} {
			r := pluginStatus(t, operatedBy, "/srv/basalt/engine.json", true, samplePluginProblem(c.code))
			p := findProblem(t, r, c.code)
			require.False(t, r.Ready, "an ERROR problem")
			require.Len(t, p.NextSteps, len(c.actions), c.code)
			for i, st := range p.NextSteps {
				require.Equal(t, c.actions[i], st.Action, c.code)
				require.Equal(t, c.cmds[i], st.Command, c.code)
				if st.Action == "RUN_COMMAND" {
					want := "PERSON"
					if operatedBy == "AGENT" {
						want = "AGENT"
					}
					require.Equal(t, want, st.Actor, c.code)
				}
			}
			require.Contains(t, p.PersonMessage, "acme-ner/client_x")
			require.NotContains(t, p.PersonMessage, "acme-ner/default", "another agent's entry is not shown")
			if operatedBy == "AGENT" {
				require.NotContains(t, p.PersonMessage, "basalt ", "the agent runs the commands")
			} else {
				require.Contains(t, p.PersonMessage, enable)
			}
		}
	}
}

// engine.json that the running engine cannot read is a WARNING naming no
// entry, with basalt plugin list to see what is wrong: the person's on a
// person-operated engine, the agent's on an agent-operated one.
func TestStatusShowsConfigInvalid(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{"", "AGENT"} {
		r := pluginStatus(t, operatedBy, "/srv/basalt/engine.json", true, fakePlugins{"bot": {{Code: ProblemPluginConfigInvalid, Message: "engine.json changed"}}})
		p := findProblem(t, r, ProblemPluginConfigInvalid)
		require.Equal(t, "WARNING", p.Severity)
		require.Equal(t, "engine.json changed", p.Message)
		require.Len(t, p.NextSteps, 1)
		require.Equal(t, "RUN_COMMAND", p.NextSteps[0].Action)
		require.Equal(t, "basalt plugin list --config /srv/basalt/engine.json", p.NextSteps[0].Command)
		require.Contains(t, p.PersonMessage, "keeps running as before")
		if operatedBy == "AGENT" {
			require.Equal(t, "AGENT", p.NextSteps[0].Actor)
			require.NotContains(t, p.PersonMessage, "basalt ")
		} else {
			require.Equal(t, "PERSON", p.NextSteps[0].Actor)
			require.Contains(t, p.PersonMessage, p.NextSteps[0].Command)
		}
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
