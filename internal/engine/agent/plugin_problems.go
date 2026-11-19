package agent

import "strings"

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
}

// PluginReporter gives the plugin problems of one agent: only entries that
// list it. Optional: without one, status says nothing about plugins.
type PluginReporter interface {
	PluginProblems(agent string) []PluginProblem
}

// pluginInstanceFlag names an entry's instance in a basalt plugin command.
const pluginInstanceFlag = "--instance"

// pluginDefaultInstance is the instance a basalt plugin command names
// without --instance.
const pluginDefaultInstance = "default"

// PluginCheck is basalt plugin check for an entry.
func (c Commands) PluginCheck(name, instance string) string {
	return c.plugin("check", name, instance)
}

// PluginDisable is basalt plugin disable for an entry; with sudo for an
// engine run as a service, where engine.json is not the person's to write.
func (c Commands) PluginDisable(name, instance string) string {
	cmd := c.plugin("disable", name, instance)
	if !c.foreground {
		cmd = "sudo " + cmd
	}
	return cmd
}

// PluginApprove is basalt plugin enable for an entry that requires
// approval: it opens a new plugin approval for the installed copy and the
// entry as engine.json holds it, and prints its link and steps. Plugin
// approvals are same-user mode only, so it never needs sudo.
func (c Commands) PluginApprove(name, instance string) string {
	return c.plugin("enable", name, instance, "--approve-with-passkey", "--json")
}

// PluginRemove is basalt plugin remove for an entry that requires approval
// (same-user mode: no sudo).
func (c Commands) PluginRemove(name, instance string) string {
	return c.plugin("remove", name, instance)
}

// PluginList is basalt plugin list, which reads engine.json and says what
// is wrong with it when it cannot.
func (c Commands) PluginList() string {
	parts := []string{cmdBasalt, "plugin", "list"}
	if c.configFlag != "" {
		parts = append(parts, c.configFlag)
	}
	return strings.Join(parts, " ")
}

func (c Commands) plugin(sub, name, instance string, flags ...string) string {
	parts := []string{cmdBasalt, "plugin", sub, name}
	if instance != "" && instance != pluginDefaultInstance {
		parts = append(parts, pluginInstanceFlag, instance)
	}
	parts = append(parts, flags...)
	if c.configFlag != "" {
		parts = append(parts, c.configFlag)
	}
	return strings.Join(parts, " ")
}

func (s statusDeps) addPluginProblems(ps *problems) {
	if s.plugins == nil {
		return
	}
	for _, p := range s.plugins.PluginProblems(s.name) {
		ps.add(p.Code, p.Message, func(b *Steps) string {
			switch p.Code {
			case ProblemPluginAwaitingApproval, ProblemPluginApprovalExpired, ProblemPluginApprovalMismatch:
				return pluginApprovalSteps(b, s.cmds, p)
			case ProblemPluginConfigInvalid:
				list := s.cmds.PluginList()
				b.MachineCommand(s.cmds, list, "Run this: it says what is wrong with engine.json. Fix that; the engine applies the plugin changes once it can read the file.",
					"Run this: it says what is wrong with engine.json. Fix what a basalt plugin command wrote, or ask the person when they edited it.")
				lead := "The engine cannot read the plugins in engine.json since it changed, so it applies no plugin change: every plugin keeps running as before."
				if s.cmds.AgentOperated() {
					return lead
				}
				return lead + " To see what is wrong, run: " + list
			}
			return pluginSteps(b, s.cmds, p)
		})
	}
}

// pluginApprovalSteps are the steps of an entry withheld for an approval
// reason (CONTRACT.md, Next steps per code). The commands are machine
// steps: the agent's on an agent-operated engine, else the person's. A
// withheld entry blocks none of the agent's calls.
func pluginApprovalSteps(b *Steps, cmds Commands, p PluginProblem) string {
	entry := p.Name + "/" + p.Instance
	approve := cmds.PluginApprove(p.Name, p.Instance)
	var lead, person string
	switch p.Code {
	case ProblemPluginAwaitingApproval:
		b.OpenGivenLink("", "Open the plugin approval link the agent gave you, check what the page shows and approve it with your passkey.")
		b.MachineCommand(cmds, approve,
			"When that link is lost or expired, or none was given, run this: it opens a new approval and prints its link.",
			"When the person no longer has a pending link, run this: it opens a new approval; hand its link to the person.")
		lead = "The plugin " + entry + " is waiting for your approval, so it does nothing for this agent yet. Open the approval link the agent gave you and approve it with your passkey: the plugin starts within a few seconds."
		person = " For a new link, run: " + approve
	case ProblemPluginApprovalExpired:
		remove := cmds.PluginRemove(p.Name, p.Instance)
		b.MachineCommand(cmds, approve, "Run this to open a new approval for the installed plugin; it prints a new link.",
			"Run this to open a new approval for the installed plugin; hand its link to the person.")
		b.MachineCommand(cmds, remove, "Or run this to remove the plugin, when you no longer want it.",
			"Or run this to remove the plugin, when the person no longer wants it.")
		lead = "The approval of the plugin " + entry + " expired before anyone signed it, so it does nothing for this agent."
		person = " To ask again, run: " + approve + " To remove it, run: " + remove
	default: // ProblemPluginApprovalMismatch
		disable := cmds.PluginDisable(p.Name, p.Instance)
		b.AskPerson("Ask the person whether they changed the plugin " + entry + " (the status message names what differs from what they approved).")
		b.MachineCommand(cmds, approve, "Run this to approve the plugin as it is now; it prints a new link.",
			"When the person says the change was theirs, run this to open a new approval; hand its link to the person.")
		b.MachineCommand(cmds, disable, "Or run this to turn the plugin off.",
			"Or, when the person does not want it, run this to turn the plugin off.")
		lead = "The plugin " + entry + " no longer matches what you approved, so it does nothing for this agent."
		person = " To approve it as it is now, run: " + approve + " To turn it off, run: " + disable
	}
	if cmds.AgentOperated() {
		// The agent runs the commands; the person only signs.
		return lead
	}
	return lead + person
}

func pluginSteps(b *Steps, cmds Commands, p PluginProblem) string {
	check, disable := cmds.PluginCheck(p.Name, p.Instance), cmds.PluginDisable(p.Name, p.Instance)
	b.RunCommand(check, "Run this to see what is wrong with the plugin.")
	b.RunCommand(disable, "Or run this to turn the plugin off.")
	entry := p.Name + "/" + p.Instance
	lead := "The plugin " + entry + " is not working, so it does nothing for this agent; while it is down, a plugin that checks the agent's requests makes them fail."
	if p.Code == ProblemPluginNotTrusted {
		lead = "The plugin " + entry + " was not started: its installed files, its signature or its directory's permissions failed the check."
	}
	return lead + " To see what is wrong, run: " + check + " To turn it off, run: " + disable
}
