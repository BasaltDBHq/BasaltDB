package status

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

func (s statusDeps) addPluginProblems(ps *guidance.Problems) {
	if s.plugins == nil {
		return
	}
	s.plugins.AddPluginProblems(ps, s.name)
}
