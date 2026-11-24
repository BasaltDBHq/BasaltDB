package status

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

// PluginReporter is what status reads of the engine's plugins: the problems
// of an agent's plugins, added to the status's list with their steps, and
// the health of the plugin entries that serve it. Optional: without one,
// status says nothing about plugins.
type PluginReporter interface {
	AddPluginProblems(ps *guidance.Problems, agent string)
	PluginHealth(agent string) []guidance.PluginHealth
}

func (s statusDeps) addPluginProblems(ps *guidance.Problems) {
	if s.plugins == nil {
		return
	}
	s.plugins.AddPluginProblems(ps, s.name)
}
