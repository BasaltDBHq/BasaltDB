package plugin

import (
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Problem codes of the status tool for plugins (api/mcp/errors/next-steps.json,
// problems).
const (
	ProblemPluginUnavailable      = "PLUGIN_UNAVAILABLE"
	ProblemPluginNotTrusted       = "PLUGIN_NOT_TRUSTED"
	ProblemPluginAwaitingApproval = "PLUGIN_AWAITING_APPROVAL"
	ProblemPluginApprovalExpired  = "PLUGIN_APPROVAL_EXPIRED"
	ProblemPluginApprovalMismatch = "PLUGIN_APPROVAL_MISMATCH"
	// ProblemPluginConfigInvalid is engine.json holding plugins the running
	// engine cannot read.
	ProblemPluginConfigInvalid = "PLUGIN_CONFIG_INVALID"
	// ProblemPluginNoticesDropped is a plugin that did not deliver some
	// approval notices.
	ProblemPluginNoticesDropped = "PLUGIN_NOTICES_DROPPED"
)

// Health values of a plugin entry in status.plugins.
const (
	PluginHealthReady    = "READY"
	PluginHealthNotReady = "NOT_READY"
)

// PluginProblem is one plugin problem of an agent, for status: Code is a
// ProblemPlugin* code, Name and Instance name the entry ("" for a problem
// that is the engine's own, like an unusable entries file), Message says what
// is wrong, EngineKept says whether the agent can change the entry with
// request_plugin (else it is in engine.json), and File is the entries file of
// a nameless problem.
type PluginProblem struct {
	Code       string
	Name       string
	Instance   string
	Message    string
	EngineKept bool
	File       string
}

// PluginEntry is an enabled plugin entry that lists the agent.
type PluginEntry struct{ Name, Instance string }

// AddPluginProblems adds the plugin problems of the agent name to ps, each
// with its steps (the status reporter's port).
func (ep *Plugins) AddPluginProblems(ps *guidance.Problems, name string) {
	addPluginProblems(ps, ep.pluginProblems(name))
}

// PluginHealth lists the plugin entries that serve the agent name, each READY
// unless a plugin problem names it; nil when it has none (the status
// reporter's port).
func (ep *Plugins) PluginHealth(name string) []guidance.PluginHealth {
	return pluginHealth(ep.pluginEntries(name), ep.pluginProblems(name))
}

func pluginArgs(p PluginProblem, remove bool) map[string]any {
	args := map[string]any{"name": p.Name, "instance": p.Instance}
	if remove {
		args["remove"] = true
	}
	return args
}

func addPluginProblems(ps *guidance.Problems, problems []PluginProblem) {
	for _, p := range problems {
		ps.Add(p.Code, p.Message, func(b *guidance.Steps) string {
			switch p.Code {
			case ProblemPluginAwaitingApproval, ProblemPluginApprovalExpired, ProblemPluginApprovalMismatch:
				return pluginApprovalSteps(b, p)
			case ProblemPluginUnavailable:
				if p.File != "" {
					return unusableFileSteps(b, ps.Cmds, p.File)
				}
			case ProblemPluginConfigInvalid:
				b.AskPerson("Tell the person engine.json was edited and its plugins cannot be read; the engine's log says what is wrong.")
				return "The engine cannot read the plugins in engine.json since it changed, so it applies no plugin change: every plugin keeps running as before. Fix the edit; the engine's log says what is wrong."
			case ProblemPluginNoticesDropped:
				return droppedNoticesSteps(b, p)
			}
			return pluginSteps(b, p)
		})
	}
}

// pluginHealth lists entries, each READY unless a plugin problem names it;
// nil when there are none.
func pluginHealth(entries []PluginEntry, probs []PluginProblem) []guidance.PluginHealth {
	if len(entries) == 0 {
		return nil
	}
	out := make([]guidance.PluginHealth, 0, len(entries))
	for _, e := range entries {
		h := guidance.PluginHealth{Name: e.Name, Instance: e.Instance, Health: PluginHealthReady}
		if i := slices.IndexFunc(probs, func(p PluginProblem) bool {
			return p.Name == e.Name && p.Instance == e.Instance && p.Code != ProblemPluginNoticesDropped
		}); i >= 0 {
			h.Health, h.Problem = PluginHealthNotReady, probs[i].Code
		}
		out = append(out, h)
	}
	return out
}

const configEntryText = " It is in engine.json, so it is changed or removed by editing that file."

func pluginApprovalSteps(b *guidance.Steps, p PluginProblem) string {
	entry := p.Name + "/" + p.Instance
	var lead string
	switch p.Code {
	case ProblemPluginAwaitingApproval:
		b.OpenGivenLink("Open the plugin approval link the agent gave you, check what the page shows and approve it with your passkey.")
		if p.EngineKept {
			b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, false),
				"Only when that link is lost or no approval is pending: call this to open a new approval, and hand its link to the person.")
		}
		lead = "The plugin " + entry + " is waiting for your approval, so it does nothing for this agent yet. Open the approval link the agent gave you and approve it with your passkey: the plugin starts within a few seconds. For a new link, ask the agent."
	case ProblemPluginApprovalExpired:
		b.AskPerson("Ask the person whether to ask for the plugin " + entry + " again, or remove it.")
		if p.EngineKept {
			b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, false), "When they want it, call this: it opens a new approval for the installed plugin.")
		}
		lead = "The approval of the plugin " + entry + " expired before anyone signed it, so it does nothing for this agent. Ask the agent to ask again, or to remove it."
	default: // ProblemPluginApprovalMismatch
		b.AskPerson("Ask the person whether they changed the plugin " + entry + " (the status message names what differs from what they approved).")
		if p.EngineKept {
			b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, false), "When the change was theirs, call this: it opens a new approval for the plugin as it is now.")
		}
		lead = "The plugin " + entry + " no longer matches what you approved, so it does nothing for this agent. If the change was yours, ask the agent for a new approval."
	}
	if !p.EngineKept {
		return lead + configEntryText
	}
	return lead
}

func unusableFileSteps(b *guidance.Steps, cmds guidance.Commands, file string) string {
	file = guidance.ShellQuote(file)
	move, restart := "sudo mv "+file+" "+file+".bad", cmds.EngineRestart()
	b.RunCommand(move, "Move the unusable entries file aside; the engine keeps no plugin until then.")
	b.RunCommand(restart, "Then restart the engine: it starts with no engine-kept plugins.")
	lead := "The engine cannot use its plugin entries file, so it serves no plugin it keeps itself."
	if cmds.AgentOperated() {
		return lead
	}
	return lead + " To move the file aside, run: " + move + " Then restart the engine: " + restart
}

func droppedNoticesSteps(b *guidance.Steps, p PluginProblem) string {
	b.CallTool(guidance.ToolListPending, map[string]any{}, "Call this to see what waits for the person's approval, and hand them the links again.")
	return "The plugin " + p.Name + "/" + p.Instance + " did not deliver some approval notices, so a link may not have reached you. " +
		"Nothing is lost: ask the agent what waits for your approval."
}

func pluginSteps(b *guidance.Steps, p PluginProblem) string {
	entry := p.Name + "/" + p.Instance
	b.AskPerson("Ask the person whether to remove the plugin " + entry + "; the status message says what is wrong with it.")
	if p.EngineKept {
		b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, true), "Only when they say so, call this to remove the plugin.")
	}
	lead := "The plugin " + entry + " is not working, so it does nothing for this agent; while it is down, a plugin that checks the agent's requests makes them fail."
	if p.Code == ProblemPluginNotTrusted {
		lead = "The plugin " + entry + " was not started: its installed files, its signature or its directory's permissions failed the check."
	}
	if !p.EngineKept {
		return lead + configEntryText
	}
	return lead + " The agent can remove it when you ask."
}
