package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// fakePlugins is the plugin reporter: the problems it adds for each agent
// (with the steps the plugin code builds, here one fixed step) and the
// health of the entries that serve it.
type fakePlugins struct {
	problems map[string][]string
	health   map[string][]guidance.PluginHealth
}

func (f fakePlugins) AddPluginProblems(ps *guidance.Problems, agent string) {
	for _, code := range f.problems[agent] {
		ps.Add(code, "plugin acme-ner/client_x is not ready (EXITED)", func(b *guidance.Steps) string {
			b.AskPerson("Ask the person whether to remove the plugin.")
			return "The plugin acme-ner/client_x is not working."
		})
	}
}

func (f fakePlugins) PluginHealth(agent string) []guidance.PluginHealth { return f.health[agent] }

func pluginStatus(t *testing.T, r PluginReporter) guidance.StatusReport {
	t.Helper()
	d := deps()
	d.Status.Plugins = r
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	rep, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return rep
}

// Status asks the plugin reporter for the plugin problems of its own agent,
// and shows what the reporter built; another agent's are not shown.
func TestStatusShowsThePluginProblemsOfItsAgent(t *testing.T) {
	t.Parallel()
	r := pluginStatus(t, fakePlugins{problems: map[string][]string{
		"bot":   {"PLUGIN_UNAVAILABLE"},
		"other": {"PLUGIN_NOT_TRUSTED"},
	}})
	p := findProblem(t, r, "PLUGIN_UNAVAILABLE")
	require.Equal(t, "plugin acme-ner/client_x is not ready (EXITED)", p.Message)
	require.Len(t, p.NextSteps, 1)
	require.Equal(t, "ASK_PERSON", p.NextSteps[0].Action)
	for _, q := range r.Problems {
		require.NotEqual(t, "PLUGIN_NOT_TRUSTED", q.Code, "another agent's problem is not shown")
	}
}

func TestNoPluginProblemWithoutAReporter(t *testing.T) {
	t.Parallel()
	r := pluginStatus(t, nil)
	for _, p := range r.Problems {
		require.NotContains(t, []string{"PLUGIN_UNAVAILABLE", "PLUGIN_NOT_TRUSTED"}, p.Code)
	}
	require.Nil(t, r.Plugins)
}
