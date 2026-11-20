package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func kinds(steps []NextStep) []mcpcontract.StepKind { return catalogKinds(steps) }

func requireConnectPending(t *testing.T, kind, code, reason string, pm string, ls []mcp.Link, steps []NextStep) {
	t.Helper()
	url := links.Portal + "/connect#" + testSetupCode
	c := catalogOf(t)
	v, ok := c.ConnectLinkEntry(kind, code, reason, "")
	require.True(t, ok)
	require.Equal(t, v.Steps, kinds(steps), "the catalog's connectLink variant")
	require.Equal(t, url, steps[0].URL)
	require.Equal(t, "OPEN_LINK", steps[0].Action)
	require.Equal(t, SetupCode(testSetupCode), steps[1].Command)
	require.Equal(t, []mcp.Link{{Label: LabelConnect, URL: url}}, ls)
	require.Contains(t, pm, "\n\n"+url+"\n\n", "the link on a line of its own")
	require.Contains(t, pm, "Basalt Vault, a hosted service")
	require.Contains(t, pm, testFingerprint)
	require.Contains(t, pm, "basalt init --setup-code")
	require.Less(t, strings.Index(pm, url), strings.Index(pm, "basalt init --setup-code"), "the link first")
	requirePersonMessage(t, pm, ls)
	for i, st := range steps {
		requireStepObeysRules(t, st, catalogCase{}, "", kind+code+reason+string(rune('0'+i)))
	}
}

func TestPendingSetupErrorHandsTheConnectLinkFirst(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		operatedBy string
		budget     int
		link       bool
	}{
		"agent-operated with the link":      {mcpcontract.OperatedByAgent, links.DefaultBudget, true},
		"vault off or not the portal":       {mcpcontract.OperatedByAgent, 0, false},
		"link over the budget":              {mcpcontract.OperatedByAgent, len(links.Portal+"/connect#"+testSetupCode) - 1, false},
		"link exactly at the budget":        {mcpcontract.OperatedByAgent, len(links.Portal + "/connect#" + testSetupCode), true},
		"person-operated engine, no budget": {"", 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := operatedService(t, "linux", "", []string{"--agent=bot", "--write=public.leads"}, tc.operatedBy)
			s.ConnectBudget = tc.budget
			te := s.Failure("query", queryArgs0, &SetupError{Code: testSetupCode, Fingerprint: testFingerprint})
			if tc.link {
				requireConnectPending(t, mcpcontract.VariantError, "UNAVAILABLE", reasonSetupPending, te.PersonMessage, te.Links, te.NextSteps)
				return
			}
			require.Empty(t, te.Links)
			require.NotContains(t, te.PersonMessage, "Vault")
			require.Equal(t, "RUN_COMMAND", te.NextSteps[0].Action)
			requireObeysCatalog(t, catalogCase{tool: "query", args: queryArgs0}, te, "", tc.operatedBy)
		})
	}
}

func TestStatusProblemsHandTheConnectLinkFirst(t *testing.T) {
	t.Parallel()
	soon := statusNow.Add(time.Hour)
	missing := &fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}
	ok := &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	for _, tc := range []struct {
		problem string
		probe   *fakeProbe
		kind    string
	}{
		{problemSetupNotRun, missing, guard.SetupInstall},
		{problemSetupChangePending, ok, guard.SetupAgent},
	} {
		t.Run(tc.problem, func(t *testing.T) {
			t.Parallel()
			d := deps()
			d.OperatedBy = mcpcontract.OperatedByAgent
			d.ConnectBudget = links.DefaultBudget
			d.Probe = tc.probe
			setApprovals(&d, keys{n: 1})
			d.Setup = pendingSetup(tc.kind, soon)
			d.Now = func() time.Time { return statusNow }
			cmds, err := NewCommands("bot", "", "linux", []string{"--agent=bot", "--write=public.leads"})
			require.NoError(t, err)
			d.Commands = cmds
			r, err := NewService(d).Status(context.Background())
			require.NoError(t, err)
			p := findProblem(t, r, tc.problem)
			requireConnectPending(t, mcpcontract.VariantProblem, tc.problem, "", p.PersonMessage, p.Links, p.NextSteps)
			statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), toolStatus)
			requireStatusSchema(t, statusTool, r)

			// With no connect budget the problem keeps the laptop command first.
			d.ConnectBudget = 0
			r, err = NewService(d).Status(context.Background())
			require.NoError(t, err)
			p = findProblem(t, r, tc.problem)
			require.Empty(t, p.Links)
			require.Equal(t, "RUN_COMMAND", p.NextSteps[0].Action)
		})
	}
}
