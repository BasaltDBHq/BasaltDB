package agent

import "strings"

// Status problems of plugin entries (CONTRACT.md, Plugins, Problems and
// errors; Next steps per code).
const (
	ProblemPluginUnavailable = "PLUGIN_UNAVAILABLE"
	ProblemPluginNotTrusted  = "PLUGIN_NOT_TRUSTED"
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

func (c Commands) plugin(sub, name, instance string) string {
	parts := []string{cmdBasalt, "plugin", sub, name}
	if instance != "" && instance != pluginDefaultInstance {
		parts = append(parts, pluginInstanceFlag, instance)
	}
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
		ps.add(p.Code, p.Message, func(b *Steps) string { return pluginSteps(b, s.cmds, p) })
	}
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
