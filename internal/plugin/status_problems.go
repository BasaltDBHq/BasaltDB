package plugin

import (
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Status problems of plugin entries (CONTRACT.md, Plugins, problems and
// errors; Next steps per code).
const (
	problemPluginUnavailable = "PLUGIN_UNAVAILABLE"
	problemPluginNotTrusted  = "PLUGIN_NOT_TRUSTED"
	// An entry that requires a plugin approval is withheld from the agent
	// for an approval reason (CONTRACT.md, Plugin approvals at engine
	// start).
	problemPluginAwaitingApproval = "PLUGIN_AWAITING_APPROVAL"
	problemPluginApprovalExpired  = "PLUGIN_APPROVAL_EXPIRED"
	problemPluginApprovalMismatch = "PLUGIN_APPROVAL_MISMATCH"
	// engine.json changed while the engine runs and its plugins cannot be
	// read, so the engine applies no plugin change (CONTRACT.md, Plugin
	// changes while the engine runs). It names no entry.
	problemPluginConfigInvalid = "PLUGIN_CONFIG_INVALID"
	// problemPluginNoticesDropped: an approval.deliver entry dropped notices
	// of this agent in the last 24 hours (CONTRACT.md, Notifier messages).
	problemPluginNoticesDropped = "PLUGIN_NOTICES_DROPPED"
)

// Health values of a plugin entry in status.plugins, as the plugin's own
// health answer names them (basalt plugin check).
const (
	pluginHealthReady    = "READY"
	pluginHealthNotReady = "NOT_READY"
)

// pluginProblem is one plugin entry listed for the agent that is not
// serving it: Code is problemPluginUnavailable or problemPluginNotTrusted.
// Message names the entry and why, never a value the plugin or its config
// gave and never another agent.
type pluginProblem struct {
	Code     string
	Name     string
	Instance string
	Message  string
	// EngineKept marks an entry the engine keeps itself (service mode, added
	// through request_plugin): only such an entry is the agent's to change;
	// one of engine.json is changed by editing that file.
	EngineKept bool
	// File is the engine's unusable entries file, for a problem that names
	// no entry: the way out is moving it aside and restarting the engine.
	File string
}

// pluginEntry is an enabled plugin entry that lists the agent.
type pluginEntry struct{ Name, Instance string }

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

// pluginArgs are the request_plugin arguments naming entry p.
func pluginArgs(p pluginProblem, remove bool) map[string]any {
	args := map[string]any{"name": p.Name, "instance": p.Instance}
	if remove {
		args["remove"] = true
	}
	return args
}

func addPluginProblems(ps *guidance.Problems, problems []pluginProblem) {
	for _, p := range problems {
		ps.Add(p.Code, p.Message, func(b *guidance.Steps) string {
			switch p.Code {
			case problemPluginAwaitingApproval, problemPluginApprovalExpired, problemPluginApprovalMismatch:
				return pluginApprovalSteps(b, p)
			case problemPluginUnavailable:
				if p.File != "" {
					return unusableFileSteps(b, ps.Cmds, p.File)
				}
			case problemPluginConfigInvalid:
				b.AskPerson("Tell the person engine.json was edited and its plugins cannot be read; the engine's log says what is wrong.")
				return "The engine cannot read the plugins in engine.json since it changed, so it applies no plugin change: every plugin keeps running as before. Fix the edit; the engine's log says what is wrong."
			case problemPluginNoticesDropped:
				return droppedNoticesSteps(b, p)
			}
			return pluginSteps(b, p)
		})
	}
}

// pluginHealth lists entries, each READY unless a plugin problem names it;
// nil when there are none.
func pluginHealth(entries []pluginEntry, probs []pluginProblem) []guidance.PluginHealth {
	if len(entries) == 0 {
		return nil
	}
	out := make([]guidance.PluginHealth, 0, len(entries))
	for _, e := range entries {
		h := guidance.PluginHealth{Name: e.Name, Instance: e.Instance, Health: pluginHealthReady}
		if i := slices.IndexFunc(probs, func(p pluginProblem) bool {
			return p.Name == e.Name && p.Instance == e.Instance && p.Code != problemPluginNoticesDropped
		}); i >= 0 {
			h.Health, h.Problem = pluginHealthNotReady, probs[i].Code
		}
		out = append(out, h)
	}
	return out
}

// configEntryText is what the person does about a plugin in engine.json:
// request_plugin changes only the plugins the engine keeps itself.
const configEntryText = " It is in engine.json, so it is changed or removed by editing that file."

func pluginApprovalSteps(b *guidance.Steps, p pluginProblem) string {
	entry := p.Name + "/" + p.Instance
	var lead string
	switch p.Code {
	case problemPluginAwaitingApproval:
		b.OpenGivenLink("Open the plugin approval link the agent gave you, check what the page shows and approve it with your passkey.")
		if p.EngineKept {
			b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, false),
				"Only when that link is lost or no approval is pending: call this to open a new approval, and hand its link to the person.")
		}
		lead = "The plugin " + entry + " is waiting for your approval, so it does nothing for this agent yet. Open the approval link the agent gave you and approve it with your passkey: the plugin starts within a few seconds. For a new link, ask the agent."
	case problemPluginApprovalExpired:
		b.AskPerson("Ask the person whether to ask for the plugin " + entry + " again, or remove it.")
		if p.EngineKept {
			b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, false), "When they want it, call this: it opens a new approval for the installed plugin.")
		}
		lead = "The approval of the plugin " + entry + " expired before anyone signed it, so it does nothing for this agent. Ask the agent to ask again, or to remove it."
	default: // problemPluginApprovalMismatch
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

func droppedNoticesSteps(b *guidance.Steps, p pluginProblem) string {
	b.CallTool(guidance.ToolListPending, map[string]any{}, "Call this to see what waits for the person's approval, and hand them the links again.")
	return "The plugin " + p.Name + "/" + p.Instance + " did not deliver some approval notices, so a link may not have reached you. " +
		"Nothing is lost: ask the agent what waits for your approval."
}

func pluginSteps(b *guidance.Steps, p pluginProblem) string {
	entry := p.Name + "/" + p.Instance
	b.AskPerson("Ask the person whether to remove the plugin " + entry + "; the status message says what is wrong with it.")
	if p.EngineKept {
		b.CallTool(guidance.ToolRequestPlugin, pluginArgs(p, true), "Only when they say so, call this to remove the plugin.")
	}
	lead := "The plugin " + entry + " is not working, so it does nothing for this agent; while it is down, a plugin that checks the agent's requests makes them fail."
	if p.Code == problemPluginNotTrusted {
		lead = "The plugin " + entry + " was not started: its installed files, its signature or its directory's permissions failed the check."
	}
	if !p.EngineKept {
		return lead + configEntryText
	}
	return lead + " The agent can remove it when you ask."
}
