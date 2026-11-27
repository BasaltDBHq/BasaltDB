package stepcatalogtest

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// PluginProblemCodes are the status problems of the plugins, which the
// plugin package runs on its own step builders (see RevertErrorKeys).
func PluginProblemCodes() []string {
	return []string{
		"PLUGIN_APPROVAL_EXPIRED", "PLUGIN_APPROVAL_MISMATCH", "PLUGIN_AWAITING_APPROVAL", "PLUGIN_CONFIG_INVALID",
		"PLUGIN_NOTICES_DROPPED", "PLUGIN_NOT_TRUSTED", "PLUGIN_UNAVAILABLE",
	}
}

func findProblemIn(t *testing.T, problems []guidance.Problem, code string) guidance.Problem {
	t.Helper()
	i := slices.IndexFunc(problems, func(p guidance.Problem) bool { return p.Code == code })
	require.GreaterOrEqual(t, i, 0, "no %s in %+v", code, problems)
	return problems[i]
}

// RequireProblemObeysCatalog checks the status problem code of a status
// report's problems (ready is the report's ready) against the catalog's entry
// for it, on an engine operated by operatedBy.
func RequireProblemObeysCatalog(t *testing.T, problems []guidance.Problem, ready bool, code, operatedBy string) {
	t.Helper()
	entry, ok := guidance.ProblemEntry(code)
	require.True(t, ok)
	p := findProblemIn(t, problems, code)
	require.Equal(t, entry.Severity, p.Severity)
	require.NotEmpty(t, p.Message)
	got := make([]mcpcontract.StepKind, 0, len(p.NextSteps))
	for _, st := range p.NextSteps {
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
	}
	want, pm, variant := ExpectedSteps(t, mcpcontract.VariantProblem, code, "", "", entry.Steps, entry.PersonMessage, operatedBy)
	require.Equal(t, want, got, "(actor, action) sequence of %s", code)
	require.Equal(t, pm, p.PersonMessage != "", "personMessage set exactly when the catalog says")
	RequireOperatorRules(t, p.NextSteps, p.PersonMessage, variant, operatedBy, code)
	RequirePersonMessage(t, p.PersonMessage, p.Links)
	for i, st := range p.NextSteps {
		where := fmt.Sprintf("%s step %d", code, i+1)
		if code == "PLUGIN_AWAITING_APPROVAL" && st.Action == toolresult.ActionOpenLink {
			// No url: the link the agent handed over when the approval was
			// opened, which the engine never had (CONTRACT.md, Next steps
			// per code).
			require.Empty(t, st.URL, where)
			require.Empty(t, st.Command, where)
			require.NotEmpty(t, st.Text, where)
			continue
		}
		RequireStepObeysRules(t, st, Case{Tool: guidance.ToolStatus, Args: map[string]any{}}, where)
	}
	require.Equal(t, entry.Severity != mcpcontract.SeverityError, ready, "ready exactly when no ERROR problem")
	for i := 1; i < len(problems); i++ {
		require.LessOrEqual(t, guidance.SeverityRank(problems[i-1].Severity), guidance.SeverityRank(problems[i].Severity), "errors first")
	}
}
