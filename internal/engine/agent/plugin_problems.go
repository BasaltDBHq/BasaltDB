package agent


// Status problems of plugin entries (CONTRACT.md, Plugins, Problems and
// errors; Next steps per code).
const (
	ProblemPluginUnavailable = "PLUGIN_UNAVAILABLE"
	ProblemPluginNotTrusted  = "PLUGIN_NOT_TRUSTED"
	// An entry that requires a plugin approval is withheld from the agent
	// for an approval reason (CONTRACT.md, Plugin approvals at engine
	// start).
	ProblemPluginAwaitingApproval = "PLUGIN_AWAITING_APPROVAL"
	ProblemPluginApprovalExpired  = "PLUGIN_APPROVAL_EXPIRED"
	ProblemPluginApprovalMismatch = "PLUGIN_APPROVAL_MISMATCH"
	// engine.json changed while the engine runs and its plugins cannot be
	// read, so the engine applies no plugin change (CONTRACT.md, Plugin
	// changes while the engine runs). It names no entry.
	ProblemPluginConfigInvalid = "PLUGIN_CONFIG_INVALID"
	// ProblemPluginNoticesDropped: an approval.deliver entry dropped notices
	// of this agent in the last 24 hours (CONTRACT.md, Notifier messages).
	ProblemPluginNoticesDropped = "PLUGIN_NOTICES_DROPPED"
)

// PluginProblem is one plugin entry listed for the agent that is not
// serving it: Code is ProblemPluginUnavailable or ProblemPluginNotTrusted.
// Message names the entry and why, never a value the plugin or its config
// gave and never another agent.
type PluginProblem struct {
	Code     string
	Name     string
	Instance string
	Message  string
	// EngineKept marks an entry the engine keeps itself (service mode, added
	// without sudo): basalt plugin disable runs without sudo for it, and
	// basalt plugin check does not find it, so its steps leave out both.
	EngineKept bool
	// File is the engine's unusable entries file, for a problem that names
	// no entry: the way out is moving it aside and restarting the engine.
	File string
}

// PluginReporter gives the plugin problems of one agent: only entries that
// list it. Optional: without one, status says nothing about plugins.
type PluginReporter interface {
	PluginProblems(agent string) []PluginProblem
}

// pluginInstanceFlag names an entry's instance in a basalt plugin command.
// pluginArgs are the request_plugin arguments naming entry p.
func pluginArgs(p PluginProblem, remove bool) map[string]any {
	args := map[string]any{"name": p.Name, "instance": p.Instance}
	if remove {
		args["remove"] = true
	}
	return args
}

func (s statusDeps) addPluginProblems(ps *problems) {
	if s.plugins == nil {
		return
	}
	for _, p := range s.plugins.PluginProblems(s.name) {
		ps.add(p.Code, p.Message, func(b *Steps) string {
			switch p.Code {
			case ProblemPluginAwaitingApproval, ProblemPluginApprovalExpired, ProblemPluginApprovalMismatch:
				return pluginApprovalSteps(b, p)
			case ProblemPluginUnavailable:
				if p.File != "" {
					return unusableFileSteps(b, s.cmds, p.File)
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

// configEntryText is what the person does about a plugin in engine.json:
// request_plugin changes only the plugins the engine keeps itself.
const configEntryText = " It is in engine.json, so it is changed or removed by editing that file."

func pluginApprovalSteps(b *Steps, p PluginProblem) string {
	entry := p.Name + "/" + p.Instance
	var lead string
	switch p.Code {
	case ProblemPluginAwaitingApproval:
		b.OpenGivenLink("", "Open the plugin approval link the agent gave you, check what the page shows and approve it with your passkey.")
		if p.EngineKept {
			b.CallTool(toolRequestPlugin, pluginArgs(p, false),
				"Only when that link is lost or no approval is pending: call this to open a new approval, and hand its link to the person.")
		}
		lead = "The plugin " + entry + " is waiting for your approval, so it does nothing for this agent yet. Open the approval link the agent gave you and approve it with your passkey: the plugin starts within a few seconds. For a new link, ask the agent."
	case ProblemPluginApprovalExpired:
		b.AskPerson("Ask the person whether to ask for the plugin " + entry + " again, or remove it.")
		if p.EngineKept {
			b.CallTool(toolRequestPlugin, pluginArgs(p, false), "When they want it, call this: it opens a new approval for the installed plugin.")
		}
		lead = "The approval of the plugin " + entry + " expired before anyone signed it, so it does nothing for this agent. Ask the agent to ask again, or to remove it."
	default: // ProblemPluginApprovalMismatch
		b.AskPerson("Ask the person whether they changed the plugin " + entry + " (the status message names what differs from what they approved).")
		if p.EngineKept {
			b.CallTool(toolRequestPlugin, pluginArgs(p, false), "When the change was theirs, call this: it opens a new approval for the plugin as it is now.")
		}
		lead = "The plugin " + entry + " no longer matches what you approved, so it does nothing for this agent. If the change was yours, ask the agent for a new approval."
	}
	if !p.EngineKept {
		return lead + configEntryText
	}
	return lead
}

func unusableFileSteps(b *Steps, cmds Commands, file string) string {
	file = shellQuote(file)
	move, restart := "sudo mv "+file+" "+file+".bad", cmds.EngineRestart()
	b.RunCommand(move, "Move the unusable entries file aside; the engine keeps no plugin until then.")
	b.RunCommand(restart, "Then restart the engine: it starts with no engine-kept plugins.")
	lead := "The engine cannot use its plugin entries file, so it serves no plugin it keeps itself."
	if cmds.AgentOperated() {
		return lead
	}
	return lead + " To move the file aside, run: " + move + " Then restart the engine: " + restart
}

func droppedNoticesSteps(b *Steps, p PluginProblem) string {
	b.CallTool(toolListPending, map[string]any{}, "Call this to see what waits for the person's approval, and hand them the links again.")
	return "The plugin " + p.Name + "/" + p.Instance + " did not deliver some approval notices, so a link may not have reached you. " +
		"Nothing is lost: ask the agent what waits for your approval."
}

func pluginSteps(b *Steps, p PluginProblem) string {
	entry := p.Name + "/" + p.Instance
	b.AskPerson("Ask the person whether to remove the plugin " + entry + "; the status message says what is wrong with it.")
	if p.EngineKept {
		b.CallTool(toolRequestPlugin, pluginArgs(p, true), "Only when they say so, call this to remove the plugin.")
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
