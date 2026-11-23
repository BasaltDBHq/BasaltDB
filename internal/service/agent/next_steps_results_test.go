package agent

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
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

type fakeRLS struct {
	hidden map[string]bool
	err    error
	asked  int
}

// Hides names a hidden table as the database does: quoted.
func (f *fakeRLS) Hides(_ context.Context, table string) (string, error) {
	f.asked++
	if f.hidden[table] {
		return `"` + strings.ReplaceAll(table, ".", `"."`) + `"`, f.err
	}
	return "", f.err
}

type fakeUpgrade struct {
	available bool
	err       error
}

func (f fakeUpgrade) UpgradeAvailable(context.Context) (bool, error) { return f.available, f.err }

func resultKey(tool, kase string) string { return tool + "|" + kase }

func pendingItem(status string, expires time.Time) PendingItem {
	n := caseNotice(caseShortLink)
	return PendingItem{
		Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: status, ExpiresAt: expires},
		Notice:   n,
	}
}

func resultCases() map[string]resultCase {
	cases := map[string]resultCase{
		resultKey("list_pending", "REQUEST_TOO_LARGE"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				n := tooLargeNotice(t, s, linksvc.KeepLink)
				item := PendingItem{
					Approval: action.Approval{ID: uuid.MustParse(caseApproval), Status: ledger.ApprovalPending, ExpiresAt: s.deps.Core.Now().Add(time.Hour)},
					Notice:   n.ApprovalNotice, tooLargeSteps: n.Steps,
				}
				person, links, steps, err := s.approval.itemGuidance(item)
				require.NoError(t, err)
				return person, links, steps
			},
		},

		resultKey("list_pending", "PENDING"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.approval.itemGuidance(pendingItem(ledger.ApprovalPending, s.deps.Core.Now().Add(time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},
		resultKey("list_pending", "EXPIRED"): {
			tool: "list_pending", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				person, links, steps, err := s.approval.itemGuidance(pendingItem(ledger.ApprovalPending, s.deps.Core.Now().Add(-time.Hour)))
				require.NoError(t, err)
				return person, links, steps
			},
		},

		resultKey("describe", "OVERVIEW_LARGE"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				b := guidance.NewSteps()
				overviewLargeSteps(b, []SchemaCount{{Schema: "app", Tables: 40}, {Schema: "billing", Tables: 12}})
				steps, err := b.Build()
				require.NoError(t, err)
				return "", nil, steps
			},
		},
		resultKey("describe", "NOT_GRANTED"): {
			tool: "describe", args: map[string]any{},
			build: func(t *testing.T, s *Service) (string, []toolresult.Link, []toolresult.NextStep) {
				b := guidance.NewSteps()
				person := s.describe.notGrantedSteps(b, 3)
				steps, err := b.Build()
				require.NoError(t, err)
				return person, nil, steps
			},
		},
	}
	maps.Copy(cases, confirmResultCases())
	maps.Copy(cases, pluginResultCases())
	return cases
}

func resultService(t *testing.T, goos, config string, opts ...func(*Deps)) *Service {
	t.Helper()
	base := func(d *Deps) {
		d.Core.PagesOrigin = "http://localhost:7878"
		d.Core.Now = func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) }
	}
	return serviceFor(t, goos, config, append([]func(*Deps){base}, opts...)...)
}

func TestEveryCatalogResultHasACase(t *testing.T) {
	t.Parallel()
	cases := resultCases()
	seen := map[string]bool{}
	var missing []string
	for _, e := range stepcatalogtest.CatalogOf(t).Results {
		key := resultKey(e.Tool, e.Case)
		seen[key] = true
		if _, ok := cases[key]; !ok && !slices.Contains(stepcatalogtest.RevertResultKeys(), key) {
			missing = append(missing, key)
		}
	}
	require.Empty(t, missing, "catalog results without a case in resultCases or in the revert package's")
	var stale []string
	for k := range cases {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	for _, k := range stepcatalogtest.RevertResultKeys() {
		require.NotContains(t, cases, k, "a revert result case runs in the revert package only")
	}
	sort.Strings(stale)
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
				continue // a revert result: it runs in the revert package
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

func TestAnApprovedPendingItemNeedsNothingFromThePerson(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	_, _, steps, err := s.approval.itemGuidance(pendingItem(ledger.ApprovalApproved, s.deps.Core.Now().Add(time.Hour)))
	require.NoError(t, err)
	require.Empty(t, steps)
}

// --- warnings ---

type warningCase struct {
	tool  string
	build func(t *testing.T, s *Service) []toolresult.Warning
}

func warningCases() map[string]warningCase {
	return map[string]warningCase{
		toolresult.WarningRLSHidesRows: {tool: "query", build: func(t *testing.T, s *Service) []toolresult.Warning {
			s.deps.Write.RLS = &fakeRLS{hidden: map[string]bool{"public.leads": true}}
			return s.write.rlsWarnings(context.Background(), []string{"public.leads"}, 0)
		}},
		toolresult.WarningGuardUpgradeAvailable: {tool: "run_start", build: func(t *testing.T, s *Service) []toolresult.Warning {
			s.deps.Status.Upgrade = fakeUpgrade{available: true}
			return s.status.upgradeWarnings(context.Background())
		}},
	}
}

func TestEveryCatalogWarningHasACase(t *testing.T) {
	t.Parallel()
	cases := warningCases()
	seen := map[string]bool{}
	for _, e := range stepcatalogtest.CatalogOf(t).Warnings {
		seen[e.Code] = true
		require.Contains(t, cases, e.Code, "catalog warning without a case in warningCases")
	}
	for code := range cases {
		require.True(t, seen[code], "warning case %s without a catalog entry", code)
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

func TestRLSWarningNamesTheTableAndOnlyAppearsOnZeroRows(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	rls := &fakeRLS{hidden: map[string]bool{"public.secrets": true}}
	s.deps.Write.RLS = rls

	require.Empty(t, s.write.rlsWarnings(context.Background(), []string{"public.secrets"}, 3), "rows came back: no warning, no check")
	require.Zero(t, rls.asked)
	require.Empty(t, s.write.rlsWarnings(context.Background(), []string{"public.leads"}, 0), "a table RLS does not hide")

	warnings := s.write.rlsWarnings(context.Background(), []string{"public.leads", "public.secrets"}, 0)
	require.Len(t, warnings, 1)
	require.Equal(t, `"public"."secrets"`, warnings[0].Table)
	require.Contains(t, warnings[0].PersonMessage, `"public"."secrets"`, "the database's name, not the agent's spelling")
}

func TestRLSCheckFailureGivesNoWarning(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")
	s.deps.Write.RLS = &fakeRLS{err: errors.New("down")}
	require.Empty(t, s.write.rlsWarnings(context.Background(), []string{"public.leads"}, 0))
	s.deps.Status.Upgrade = fakeUpgrade{err: errors.New("down")}
	require.Empty(t, s.status.upgradeWarnings(context.Background()))
	s.deps.Status.Upgrade = fakeUpgrade{}
	require.Empty(t, s.status.upgradeWarnings(context.Background()), "no migration missing: no warning")
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

// Text the database supplies cannot fake a link line in a message the
// person reads: a table whose name holds one.
func TestSuppliedTextCannotFakeALinkInAPersonMessage(t *testing.T) {
	t.Parallel()
	s := resultService(t, "linux", "")

	table := "public.x\n\nhttps://evil.example/pay\n\ny"
	s.deps.Write.RLS = &fakeRLS{hidden: map[string]bool{table: true}}
	warnings := s.write.rlsWarnings(context.Background(), []string{table}, 0)
	require.Len(t, warnings, 1)
	mcptest.Require(t, warnings[0].PersonMessage, nil)
	require.NotContains(t, warnings[0].PersonMessage, "://")
}
