package agent

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The warning cases of the catalog that the agent use case builds run here,
// on the use case itself: each builds the warning with the use case's own
// code. Their codes are stepcatalogtest's AgentWarningCodes; the agent
// service's tests cover the rest of the catalog and require these beside
// their own.

type warningCase struct {
	tool string
	// opts are set before the service is built.
	opts  []option
	build func(t *testing.T, s *Service) []toolresult.Warning
}

func warningCases() map[string]warningCase {
	return map[string]warningCase{
		toolresult.WarningRLSHidesRows: {
			tool: "query",
			opts: []option{withRLS(&fakeRLS{hidden: map[string]bool{"public.leads": true}})},
			build: func(t *testing.T, s *Service) []toolresult.Warning {
				return s.rlsWarnings(context.Background(), []string{"public.leads"}, 0)
			},
		},
	}
}

func TestAgentWarningCasesAreTheOnesTheAgentExpects(t *testing.T) {
	t.Parallel()
	codes := make([]string, 0, len(warningCases()))
	for code := range warningCases() {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	require.Equal(t, stepcatalogtest.AgentWarningCodes(), codes)
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Warnings {
		seen[e.Code] = true
	}
	for _, code := range codes {
		require.True(t, seen[code], "warning case %s without a catalog entry", code)
	}
}

func TestEveryAgentCatalogWarningGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct{ name, goos, config string }{
		{"default config", "linux", ""},
		{"custom config", "darwin", "/srv/basalt/engine.json"},
	} {
		for _, entry := range stepcatalogtest.CatalogOf(t).Warnings {
			kase, ok := warningCases()[entry.Code]
			if !ok {
				continue // another package's: the agent service runs it
			}
			t.Run(variant.name+"/"+entry.Code, func(t *testing.T) {
				t.Parallel()
				s := newTestService(t, variant.goos, variant.config, kase.opts...)
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
func TestEveryAgentCatalogWarningGivesTheVariantOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	for _, entry := range stepcatalogtest.CatalogOf(t).Warnings {
		kase, ok := warningCases()[entry.Code]
		if !ok {
			continue // another package's: the agent service runs it
		}
		t.Run(entry.Code, func(t *testing.T) {
			t.Parallel()
			s := newTestService(t, "linux", "", append([]option{withOperatedBy(mcpcontract.OperatedByAgent)}, kase.opts...)...)
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

func TestRLSWarningNamesTheTableAndOnlyAppearsOnZeroRows(t *testing.T) {
	t.Parallel()
	rls := &fakeRLS{hidden: map[string]bool{"public.secrets": true}}
	s := newTestService(t, "linux", "", withRLS(rls))

	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.secrets"}, 3), "rows came back: no warning, no check")
	require.Zero(t, rls.asked)
	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.leads"}, 0), "a table RLS does not hide")

	warnings := s.rlsWarnings(context.Background(), []string{"public.leads", "public.secrets"}, 0)
	require.Len(t, warnings, 1)
	require.Equal(t, `"public"."secrets"`, warnings[0].Table)
	require.Contains(t, warnings[0].PersonMessage, `"public"."secrets"`, "the database's name, not the agent's spelling")
}

func TestRLSCheckFailureGivesNoWarning(t *testing.T) {
	t.Parallel()
	s := newTestService(t, "linux", "", withRLS(&fakeRLS{err: errors.New("down")}))
	require.Empty(t, s.rlsWarnings(context.Background(), []string{"public.leads"}, 0))
}

// Text the database supplies cannot fake a link line in a message the
// person reads: a table whose name holds one.
func TestSuppliedTextCannotFakeALinkInAPersonMessage(t *testing.T) {
	t.Parallel()
	table := "public.x\n\nhttps://evil.example/pay\n\ny"
	s := newTestService(t, "linux", "", withRLS(&fakeRLS{hidden: map[string]bool{table: true}}))
	warnings := s.rlsWarnings(context.Background(), []string{table}, 0)
	require.Len(t, warnings, 1)
	mcptest.Require(t, warnings[0].PersonMessage, nil)
	require.NotContains(t, warnings[0].PersonMessage, "://")
}

func TestBlindCacheAsksOncePerTableUntilRefreshed(t *testing.T) {
	t.Parallel()
	asked := 0
	hidden := true
	cache := NewBlindCache(func(_ context.Context, tables []string) ([]string, error) {
		asked++
		if hidden {
			return []string{"public.leads"}, nil
		}
		return nil, nil
	})
	for range 3 {
		got, err := cache.Hides(context.Background(), "leads")
		require.NoError(t, err)
		require.Equal(t, "public.leads", got)
	}
	require.Equal(t, 1, asked)

	hidden = false
	got, err := cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Equal(t, "public.leads", got, "still the cached answer")
	cache.Refresh()
	got, err = cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Empty(t, got, "refreshed with the upkeep cycle")
	require.Equal(t, 2, asked)
}

// A refresh between the question and the store must not leave the old answer.
func TestBlindCacheDropsAnAnswerAskedBeforeARefresh(t *testing.T) {
	t.Parallel()
	var cache *BlindCache
	cache = NewBlindCache(func(context.Context, []string) ([]string, error) {
		cache.Refresh() // the upkeep cycle runs while the question is out
		return []string{"public.leads"}, nil
	})
	got, err := cache.Hides(context.Background(), "leads")
	require.NoError(t, err)
	require.Equal(t, "public.leads", got)
	require.Empty(t, cache.known, "the stale answer was not stored")
}
