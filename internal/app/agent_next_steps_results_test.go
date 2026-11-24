package app

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// resultCase builds one result of the catalog: the person's message and the
// next steps it carries, for the tool and the call that returned it.
type resultCase struct {
	tool string
	args map[string]any
	// build returns the result's personMessage and nextSteps.
	build func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep)
	// openWithoutURL marks the one OPEN_LINK that names no url: the short
	// link the agent gave earlier.
	openWithoutURL bool
}

type fakeUpgrade struct {
	available bool
	err       error
}

func (f fakeUpgrade) UpgradeAvailable(context.Context) (bool, error) { return f.available, f.err }

func resultKey(tool, kase string) string { return tool + "|" + kase }

func resultCases() map[string]resultCase {
	cases := map[string]resultCase{
		resultKey("describe", "OVERVIEW_LARGE"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				o, err := describeUseCase(guidance.Commands{}, &fakeCatalog{visible: manySchemas(2, map[string]int{"tenant_00000": 39, "tenant_00001": 11})}).DescribeOverview(context.Background())
				require.NoError(t, err)
				return o.PersonMessage, nil, o.NextSteps
			},
		},
		resultKey("describe", "NOT_GRANTED"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				o, err := describeUseCase(guidance.Commands{}, &fakeCatalog{notGranted: 3}).DescribeOverview(context.Background())
				require.NoError(t, err)
				return o.PersonMessage, nil, o.NextSteps
			},
		},
	}
	maps.Copy(cases, confirmResultCases())
	return cases
}

func resultService(t *testing.T, goos, config string) *Service {
	t.Helper()
	base := func(d *Deps) {
		d.Core.PagesOrigin = "http://localhost:7878"
		d.Core.Now = func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) }
	}
	return serviceFor(t, goos, config, base)
}

func TestEveryCatalogResultHasACase(t *testing.T) {
	t.Parallel()
	cases := resultCases()
	seen := map[string]bool{}
	var missing []string
	for _, e := range stepcatalogtest.CatalogOf(t).Results {
		key := resultKey(e.Tool, e.Case)
		seen[key] = true
		if _, ok := cases[key]; !ok && !slices.Contains(stepcatalogtest.RevertResultKeys(), key) && !slices.Contains(stepcatalogtest.ApprovalResultKeys(), key) && !slices.Contains(stepcatalogtest.PluginResultKeys(), key) {
			missing = append(missing, key)
		}
	}
	require.Empty(t, missing, "catalog results without a case in resultCases or in the revert, approval or plugin package's")
	var stale []string
	for k := range cases {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	for _, k := range slices.Concat(stepcatalogtest.RevertResultKeys(), stepcatalogtest.ApprovalResultKeys(), stepcatalogtest.PluginResultKeys()) {
		require.NotContains(t, cases, k, "a revert, approval or plugin result case runs in its own package only")
	}
	slices.Sort(stale)
	require.Empty(t, stale, "result cases without a catalog entry")
}

func TestEveryCatalogResultGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct {
		name, goos, config string
		initArgs           []string
	}{
		{"default config", "linux", "", []string{"--agent=bot", "--write=public.leads"}},
		{"custom config", "darwin", "/srv/basalt/engine.json", []string{"--agent=bot", "--read=public.leads"}},
	} {
		for _, entry := range stepcatalogtest.CatalogOf(t).Results {
			kase, ok := resultCases()[resultKey(entry.Tool, entry.Case)]
			if !ok {
				continue // a revert or approval result: it runs in its own package
			}
			t.Run(variant.name+"/"+resultKey(entry.Tool, entry.Case), func(t *testing.T) {
				t.Parallel()
				s := resultService(t, variant.goos, variant.config)
				person, links, steps := kase.build(t, s)
				stepcatalogtest.RequireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					stepcatalogtest.Case{Tool: kase.tool, Args: kase.args}, person, links, steps, kase.openWithoutURL)
			})
		}
	}
}

// --- warnings ---

type warningCase struct {
	tool  string
	build func(t *testing.T, s *Service) []toolresult.Warning
}

func warningCases() map[string]warningCase {
	return map[string]warningCase{
		toolresult.WarningGuardUpgradeAvailable: {tool: "run_start", build: func(t *testing.T, s *Service) []toolresult.Warning {
			s.deps.Status.Upgrade = fakeUpgrade{available: true}
			return s.status.UpgradeWarnings(context.Background())
		}},
	}
}

func TestEveryCatalogWarningHasACase(t *testing.T) {
	t.Parallel()
	cases := warningCases()
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Warnings {
		seen[e.Code] = true
		if !slices.Contains(stepcatalogtest.AgentWarningCodes(), e.Code) {
			require.Contains(t, cases, e.Code, "catalog warning without a case in warningCases or in the agent package's")
		}
	}
	for code := range cases {
		require.True(t, seen[code], "warning case %s without a catalog entry", code)
		require.NotContains(t, stepcatalogtest.AgentWarningCodes(), code, "an agent warning case runs in its own package only")
	}
}

func TestEveryCatalogWarningGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct {
		name, goos, config string
		initArgs           []string
	}{
		{"default config", "linux", "", []string{"--agent=bot", "--write=public.leads"}},
		{"custom config", "darwin", "/srv/basalt/engine.json", []string{"--agent=bot", "--read=public.leads"}},
	} {
		for _, entry := range stepcatalogtest.CatalogOf(t).Warnings {
			if slices.Contains(stepcatalogtest.AgentWarningCodes(), entry.Code) {
				continue // it runs in the agent package
			}
			kase := warningCases()[entry.Code]
			t.Run(variant.name+"/"+entry.Code, func(t *testing.T) {
				t.Parallel()
				s := resultService(t, variant.goos, variant.config)
				warnings := kase.build(t, s)
				require.Len(t, warnings, 1)
				w := warnings[0]
				require.Equal(t, entry.Code, w.Code)
				require.NotEmpty(t, w.Message)
				stepcatalogtest.RequireObeysCatalogSteps(t, mcpcontract.ErrorSteps{PersonMessage: entry.PersonMessage, Steps: entry.Steps},
					stepcatalogtest.Case{Tool: kase.tool}, w.PersonMessage, nil, w.NextSteps, false)
			})
		}
	}
}

// On an agent-operated engine each warning takes its agentOperated variant:
// the agent makes a setup code instead of the person running an admin
// command on the agent's machine.
func TestEveryCatalogWarningGivesTheVariantOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	for _, entry := range stepcatalogtest.CatalogOf(t).Warnings {
		if slices.Contains(stepcatalogtest.AgentWarningCodes(), entry.Code) {
			continue // it runs in the agent package
		}
		kase := warningCases()[entry.Code]
		t.Run(entry.Code, func(t *testing.T) {
			t.Parallel()
			s := operatedService(t, "linux", "", mcpcontract.OperatedByAgent, func(d *Deps) { d.Core.PagesOrigin = "http://localhost:7878" })
			warnings := kase.build(t, s)
			require.Len(t, warnings, 1)
			w := warnings[0]
			want, pm, variant := stepcatalogtest.ExpectedSteps(t, mcpcontract.VariantWarning, entry.Code, "", "", entry.Steps, entry.PersonMessage, mcpcontract.OperatedByAgent)
			got := make([]mcpcontract.StepKind, 0, len(w.NextSteps))
			for _, st := range w.NextSteps {
				got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
			}
			require.Equal(t, want, got)
			require.Equal(t, pm, w.PersonMessage != "")
			mcptest.Require(t, w.PersonMessage, nil)
			stepcatalogtest.RequireOperatorRules(t, w.NextSteps, w.PersonMessage, variant, mcpcontract.OperatedByAgent, entry.Code)
			for i, st := range w.NextSteps {
				stepcatalogtest.RequireStepObeysRules(t, st, stepcatalogtest.Case{Tool: kase.tool}, "step "+strconv.Itoa(i+1))
			}
		})
	}
}

func TestUpgradeCheckFailureGivesNoWarning(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	s.deps.Status.Upgrade = fakeUpgrade{err: errors.New("down")}
	require.Empty(t, s.status.UpgradeWarnings(context.Background()))
	s.deps.Status.Upgrade = fakeUpgrade{}
	require.Empty(t, s.status.UpgradeWarnings(context.Background()), "no migration missing: no warning")
}
