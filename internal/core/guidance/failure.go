package guidance

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ReasonAdminCredential is INVALID_ARGUMENT for a tool call whose arguments
// hold a Postgres connection URL with a password (CONTRACT.md, Agents and
// the admin credential).
const ReasonAdminCredential = "ADMIN_CREDENTIAL" //nolint:gosec // an error reason, not a credential

const (
	adminCredentialAsk = "Tell the person that a database connection string with a password was in your call and that basalt did not keep it, " +
		"and ask them to change that database password now. Do not repeat or use the string."
	adminCredentialRevise = "Then call again without the connection string. To set up, run basalt init (basalt init --remote where the person cannot reach this computer) and show the person the link it prints."
	// AdminCredentialPerson is the person's message of an admin-credential refusal.
	AdminCredentialPerson = "A database connection string with a password was sent through your agent. BasaltDB refused the call and kept no copy. Change that database password now."
)

// Failure is the call an error answers: the tool and its arguments.
type Failure struct {
	Tool string
	Args map[string]any
	Err  error
}

// Arg is the string argument name of the call, "" when it has none.
func (f Failure) Arg(name string) string {
	s, _ := f.Args[name].(string)
	return s
}

// DescribeTimeoutText is the revision a describe that ran out of time asks
// for, by form: a narrower search, or a search in place of the whole
// overview or table.
func DescribeTimeoutText(f Failure) string {
	switch {
	case f.Arg(ArgQuery) != "":
		return "Search with a longer, more specific query so the catalog answers in time, then call describe again."
	case f.Arg(ArgResource) != "":
		return "The catalog was slow: call describe for this resource once more, or search with a query for the fields you need."
	}
	return "The catalog was slow: call describe once more, or search with a query for the resources you need."
}

// rowTooLargeTools are the tools whose own statement's rows the agent
// reads: query, and a write's RETURNING.
var rowTooLargeTools = map[string]bool{ToolQuery: true, ToolWrite: true}

// RowTooLargeTool reports whether tool is one whose own statement's rows
// the agent reads, so that a row too large for the budget is
// QUERY_TIMEOUT ROW_TOO_LARGE for it.
func RowTooLargeTool(tool string) bool { return rowTooLargeTools[tool] }

// InvalidArgumentSteps are the next steps of an INVALID_ARGUMENT by reason.
// It returns the person's message when the reason has one.
func InvalidArgumentSteps(b *Steps, te *toolresult.ToolError, f Failure) string {
	switch te.Reason {
	case ReasonStaleCursor:
		b.RepeatCall(f.Tool, map[string]any{"cursor": nil}, 0, "The cursor is no longer valid: call again without cursor to start from the first page.")
		return ""
	case ReasonScopeFilter:
		b.ReviseCall(f.Tool, nil, "Call again without the refused entries the message names, or without that filter.")
		if id := f.Arg(ArgRunID); id != "" {
			b.CallTool(ToolRunHistory, map[string]any{ArgRunID: id}, "Read the run's history to see the resources you wrote in it.")
			return ""
		}
		b.CallTool(ToolListRuns, map[string]any{}, "List your runs to see your own runs in the task; run_history shows the resources each one wrote.")
		return ""
	case ReasonScopeFilterCap:
		b.ReviseCall(f.Tool, nil, fmt.Sprintf("Call again with at most %d runs and %d resources, or without the filter: the person "+
			"can narrow it on the signing page.", revert.MaxFilter, revert.MaxFilter))
		return ""
	case ReasonAdminCredential:
		b.AskPerson(adminCredentialAsk)
		b.ReviseCall(f.Tool, nil, adminCredentialRevise)
		return AdminCredentialPerson
	}
	b.FixArguments(f.Tool)
	return ""
}
