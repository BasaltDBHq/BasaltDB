package agent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
)

// Failure maps err, raised by a call of tool with args, to the contract's
// error body (CONTRACT.md, Error codes and Next steps): code and reason,
// the message, the next steps and the person's message the catalog
// prescribes. Every tool error passes through it, so none reaches the agent
// bare. A body that already carries its steps (built where the engine
// knows the link or the ledger row) keeps them.
func (s *Service) Failure(tool string, args map[string]any, err error) *toolresult.ToolError {
	te := rowTooLargeFor(tool, guidance.MessageTooLarge(tool, err, s.core.Errors.ToolError(err)))
	if te.Code == guidance.CodeInternal || te.Code == guidance.CodeUnavailable {
		if te.ErrorID == "" {
			te.ErrorID = uniqueid.New()
		}
		s.core.Log.Error("tool failed", "tool", tool, "code", te.Code, "reason", te.Reason, "error_id", te.ErrorID, "err", err)
	}
	s.addGuidance(te, guidance.Failure{Tool: tool, Args: args, Err: err})
	return te
}

// addGuidance fills te's next steps and person message from the catalog's
// entry for its code, reason and tool. A missing entry or a body that
// disagrees with it is a defect: it is logged here, and the catalog test
// fails on it.
func (s *Service) addGuidance(te *toolresult.ToolError, f guidance.Failure) {
	entry, ok := guidance.Catalog().ErrorEntry(te.Code, te.Reason, f.Tool)
	if !ok {
		s.core.Log.Error("no catalog entry for the error", "code", te.Code, "reason", te.Reason, "tool", f.Tool)
		return
	}
	if len(te.NextSteps) == 0 {
		steps, person, err := s.errorGuidance(te, f)
		if err != nil {
			s.core.Log.Error("cannot build next steps", "code", te.Code, "reason", te.Reason, "tool", f.Tool, "err", err)
			return
		}
		te.NextSteps = steps
		if te.PersonMessage == "" {
			te.PersonMessage = guidance.FitToSteps(person, steps)
		}
	}
	if err := guidance.CheckPersonMessage(te.PersonMessage); err != nil {
		s.core.Log.Error("person message breaks its limit", "code", te.Code, "reason", te.Reason, "tool", f.Tool, "err", err)
	}
	if entry.PersonMessage != (te.PersonMessage != "") {
		s.core.Log.Error("person message disagrees with the catalog", "code", te.Code, "reason", te.Reason, "tool", f.Tool)
	}
}

// errorGuidance builds the steps and the person message for te, by code.
func (s *Service) errorGuidance(te *toolresult.ToolError, f guidance.Failure) ([]toolresult.NextStep, string, error) {
	b, person := guidance.NewSteps(), ""
	switch te.Code {
	case guidance.CodeIntentRequired:
		b.ReviseCall(f.Tool, nil, "Add an intent, one sentence saying why the change is made, then call write again.")
	case guidance.CodeStaleRead:
		s.staleReadSteps(b, te, f)
	case guidance.CodeStatementRefused:
		if te.Reason == action.ReasonHoldTooLarge {
			person = s.approvals.HoldTooLargeSteps(b, te)
			break
		}
		person = refusedSteps(b, te, f)
	case guidance.CodeRowLimitExceeded:
		person = rowLimitSteps(b)
	case guidance.CodeQueryTimeout:
		queryTimeoutSteps(b, te, f)
	case guidance.CodeApprovalRequired:
		person = s.approvals.ApprovalRequiredSteps(b, te)
	case guidance.CodeApprovalExpired:
		guidance.ApprovalExpiredSteps(b)
		person = approvalsvc.ApprovalExpiredMessage
	case guidance.CodeApprovalInvalid:
		person = approvalsvc.ApprovalInvalidSteps(b, te, f.Arg(guidance.ArgRunID))
	case guidance.CodeRevertInvalid:
		revertsvc.InvalidSteps(b, te, f.Arg(guidance.ArgRevertID))
	case guidance.CodePermissionDenied:
		person = s.permissionDeniedSteps(b, te, f)
	case guidance.CodeNotFound:
		if f.Tool == guidance.ToolDescribe {
			person = s.describeNotFoundSteps(b, f)
			break
		}
		person = notFoundSteps(b, te, f)
	case guidance.CodeSQLError:
		sqlErrorSteps(b, te, f)
	case guidance.CodeInvalidArgument:
		person = guidance.InvalidArgumentSteps(b, te, f)
	case guidance.CodeUnavailable:
		person = s.steps.UnavailableSteps(b, te, f)
	case guidance.CodeInternal:
		b.Stop("Do not retry: the engine failed. Tell the person the error id so they can find it in the engine's log.")
		person = fmt.Sprintf("Basalt hit an internal error and stopped this action. The engine's log has the details under error id %s.", te.ErrorID)
	default:
		return nil, "", fmt.Errorf("no guidance for code %s", te.Code)
	}
	steps, err := b.Build()
	return steps, person, err
}

var staleDetail = regexp.MustCompile(`^STALE_READ: (.+?) (\{.*\}) read at xmin \d+, now \d+`)

// staleReadSteps: read the row again, then decide. The guard's detail names
// the table and the key (`public.leads {"id": 42} read at xmin 7, now 9`);
// the step is the query that reads that row. Decided here, provisionally:
// the engine parses the detail, whose format a test against a real guard
// pins, instead of a guard migration to a JSON detail.
func (s *Service) staleReadSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) {
	args, err := staleReadQuery(te.Message, f.Arg(guidance.ArgRunID))
	if err != nil {
		// A detail the engine cannot read: the catalog's query step cannot be
		// filled in, so the agent stops and asks instead of guessing a row.
		s.core.Log.Error("stale read detail not understood", "err", err)
		b.Stop("Do not write on the old read, and do not retry the write as it is.")
		b.AskPerson("Tell the person the row changed since you read it, and ask how to go on.")
		return
	}
	b.CallTool(guidance.ToolQuery, args, "Read the row again in this run, then decide.")
	b.ReviseCall(guidance.ToolWrite, nil, "Decide again from what the row holds now, then send the write again with the same intent.")
}

// staleReadQuery is the query arguments that read the row a STALE_READ
// message names.
func staleReadQuery(message, runID string) (map[string]any, error) {
	m := staleDetail.FindStringSubmatch(message)
	if m == nil {
		return nil, fmt.Errorf("cannot read the table and key from the stale read detail %q", message)
	}
	var key map[string]any
	dec := json.NewDecoder(strings.NewReader(m[2]))
	dec.UseNumber()
	if err := dec.Decode(&key); err != nil || len(key) == 0 {
		return nil, fmt.Errorf("cannot read the key of the stale read: %q", m[2])
	}
	cols := make([]string, 0, len(key))
	for c := range key {
		cols = append(cols, c)
	}
	slices.Sort(cols)
	conds, params := make([]string, 0, len(cols)), make([]any, 0, len(cols))
	for i, c := range cols {
		conds = append(conds, fmt.Sprintf("%s = $%d", sanitizeIdent(c), i+1))
		params = append(params, key[c])
	}
	args := map[string]any{"sql": "SELECT * FROM " + m[1] + " WHERE " + strings.Join(conds, " AND "), "params": params}
	if runID != "" {
		args[guidance.ArgRunID] = runID
	}
	return args, nil
}

// refusedText is the revision each statement refusal asks for.
var refusedText = map[string]string{
	string(action.ReasonParseError):         "Fix the SQL syntax as the message says, then call again.",
	string(action.ReasonMultipleStatements): "Send exactly one statement per call: split it into separate calls.",
	string(action.ReasonWrongTool):          "Send SELECT with query, and INSERT, UPDATE and DELETE with write.",
	string(action.ReasonUtility):            "Only SELECT (query) and INSERT, UPDATE, DELETE (write) are allowed: use one of them.",
	string(action.ReasonSelectInto):         "SELECT INTO creates a table: rewrite it as a plain SELECT.",
	string(action.ReasonLockingRead):        "Drop FOR UPDATE and the other lock clauses: query reads without locking.",
	string(action.ReasonMerge):              "MERGE is not allowed: use separate INSERT, UPDATE and DELETE statements.",
	string(action.ReasonDataModifyingWith):  "Move the INSERT, UPDATE or DELETE out of the WITH and send it as its own write.",
	string(action.ReasonFunction):           "Remove the call to the refused function the message names and use plain SQL.",
	string(action.ReasonNotRepeatable):      "Rewrite the write with fixed values instead of ones that change between runs, then call it again.",
}

// refusedSteps: most refusals are fixed by rewriting the statement; DDL and
// the guard's own refusals are not the agent's to get around.
func refusedSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	switch te.Reason {
	case string(action.ReasonDDL):
		b.Stop("Do not retry and do not look for another way to change the schema.")
		b.AskPerson("Tell the person which schema change you need; they make it themselves.")
		return "The agent tried to change the database schema (DDL). Basalt never lets an agent do that. Make the change yourself if you want it."
	case guidance.ReasonNoPrimaryKey:
		b.Stop("The table has no primary key, so its writes cannot be recorded: do not retry or work around it.")
		return fmt.Sprintf("%s has no primary key, so Basalt cannot guard writes to it and refuses them. Add a primary key to the table, "+
			"or revoke the agent's write access to it.", guidance.Shown(tableFromDetail(te.Message), guidance.MaxTableChars))
	case guidance.ReasonNotAllowed:
		b.Stop("The database refused this action for the agent: do not retry or work around it.")
		return ""
	}
	tool := f.Tool
	if te.Reason == string(action.ReasonWrongTool) {
		tool = guidance.ToolQuery // the statement went to write: it reads
		if f.Tool == guidance.ToolQuery {
			tool = guidance.ToolWrite
		}
	}
	b.ReviseCall(tool, nil, refusedText[te.Reason])
	return ""
}

var noPrimaryKey = regexp.MustCompile(`table (\S+) has no primary key`)

func tableFromDetail(message string) string {
	if m := noPrimaryKey.FindStringSubmatch(message); m != nil {
		return m[1]
	}
	return "The table"
}

// rowLimitSteps: over the hold limit the agent stops and asks; only on the
// person's explicit yes does it split into held batches of the most a hold
// takes, each needing the person's approval (AE-7).
func rowLimitSteps(b *guidance.Steps) string {
	b.Stop("Do not split the write to get around the limit, and do not retry it as it is.")
	b.AskPerson(fmt.Sprintf("Tell the person the write touches more than %d rows, cascades included, and ask whether to run it in held batches.", guidance.MaxRetryRows))
	b.RetrySmallerBatches(guidance.MaxRetryRows, fmt.Sprintf("Do this only on an explicit yes: write in batches of at most %d rows, same intent and run; the person approves each batch.", guidance.MaxRetryRows))
	return fmt.Sprintf("The agent's write touches more than %d rows (cascades included). It will ask you whether to run it in batches of up to %d rows; "+
		"you approve each batch with your passkey.", guidance.MaxRetryRows, guidance.MaxRetryRows)
}

func queryTimeoutSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) {
	if f.Tool == guidance.ToolDescribe {
		b.ReviseCall(f.Tool, nil, guidance.DescribeTimeoutText(f))
		return
	}
	switch te.Reason {
	case guidance.ReasonRowLimit:
		b.ReviseCall(f.Tool, nil, "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.")
		return
	case guidance.ReasonSizeLimit:
		b.ReviseCall(f.Tool, nil, sizeLimitText(f.Tool))
		return
	case guidance.ReasonRowTooLarge:
		b.ReviseCall(f.Tool, nil, "One row is too large to read whole: select fewer columns, the size of a large one "+
			"(length(col)) or a slice of it (substr(col, 1, 100000)), then call it again.")
		return
	}
	b.ReviseCall(f.Tool, nil, "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again.")
}

// rowTooLargeFor keeps ROW_TOO_LARGE for the tools whose statement it
// refuses (CONTRACT.md, QUERY_TIMEOUT ROW_TOO_LARGE); any other tool's
// read too large for the budget is SIZE_LIMIT.
func rowTooLargeFor(tool string, te *toolresult.ToolError) *toolresult.ToolError {
	if te.Code == guidance.CodeQueryTimeout && te.Reason == guidance.ReasonRowTooLarge && !guidance.RowTooLargeTool(tool) {
		te = guidance.SizeLimitError()
	}
	if te.Code == guidance.CodeQueryTimeout && te.Reason == guidance.ReasonSizeLimit && pagedTools[tool] {
		// A paged tool's message names its step, not the columns of a query.
		te.Message = budget.ErrSizeLimit.Error() + "; call it again with a smaller limit, down to 1"
	}
	return te
}

// pagedTools page ledger items with limit: a smaller limit ends a
// SIZE_LIMIT (CONTRACT.md, Large values).
var pagedTools = map[string]bool{guidance.ToolRunHistory: true, guidance.ToolListPending: true, guidance.ToolPreviewRevert: true, guidance.ToolRevertPlan: true}

// sizeLimitText is what the agent revises after SIZE_LIMIT, by tool
// (CONTRACT.md, Next steps per code): a smaller page for the paged tools, a
// narrower revert for request_revert, fewer or shorter values otherwise.
func sizeLimitText(tool string) string {
	switch tool {
	case guidance.ToolRunHistory, guidance.ToolListPending, guidance.ToolPreviewRevert, guidance.ToolRevertPlan:
		return "Call it again with a smaller limit (half of it, for example) so the result stays under 16 MiB."
	case guidance.ToolRequestRevert:
		return "Request a narrower revert, with runs or tables, so its lines stay under 16 MiB."
	}
	return "Select fewer or shorter columns (for example left(col, 200)) or fewer rows so the result stays under 16 MiB, then call it again."
}

var deniedTable = regexp.MustCompile(`permission denied for (?:table|relation) (\S+)`)

// permissionDeniedSteps: the agent asks, and only when the person tells it
// to add the access, in a later turn, runs basalt init, whose link opens the
// page where the person grants it (RI-16). The message names the table
// Postgres named, never a command.
func (s *Service) permissionDeniedSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	b.Stop("The agent role may not do this: do not retry or look for another route.")
	access := "write"
	if f.Tool == guidance.ToolQuery {
		access = "read"
	}
	what := "access to what it asked for"
	if m := deniedTable.FindStringSubmatch(te.Message); m != nil {
		what = access + " access to " + guidance.Shown(m[1], guidance.MaxTableChars)
	}
	b.AskPerson("Tell the person which access is missing and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the access once you decide it should have it.")
	b.EndTurn("End your turn: the person decides.")
	b.AgentRunCommand(s.core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the access.")
	return fmt.Sprintf("The agent was denied %s. If it should have it, tell the agent: it gives you a link where you grant it.", what)
}

func notFoundSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	switch te.Reason {
	case guidance.ReasonRun:
		b.CallTool(guidance.ToolListRuns, map[string]any{}, "List your runs, or start a new one with run_start.")
	case guidance.ReasonChange:
		if id := f.Arg(guidance.ArgRunID); id != "" {
			b.CallTool(guidance.ToolRunHistory, map[string]any{guidance.ArgRunID: id}, "Read the run's history to find the id of the change you mean.")
			return ""
		}
		b.CallTool(guidance.ToolListRuns, map[string]any{}, "List your runs, then read one run's history for the change id.")
	case guidance.ReasonApproval:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "List your pending approvals to find the right approvalId.")
	case guidance.ReasonRevert:
		b.AskPerson("Ask the person which revert they mean; this agent prepared no revert with that id.")
	case guidance.ReasonLink:
		b.TellAgent("Ask the agent for the link again.")
		return "This link is incomplete, expired or was replaced by a newer one. Ask the agent for the link again."
	case guidance.ReasonLinkReset:
		b.TellAgent("Ask the agent for the new link to this revert.")
		return linksvc.LinkResetMessage
	default:
		b.Fail(fmt.Errorf("NOT_FOUND has no reason %q", te.Reason))
	}
	return ""
}

func sqlErrorSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) {
	if te.Reason == guidance.ReasonNoRowsNow {
		b.ReviseCall(f.Tool, nil, "The write now changes no rows: read the rows again with query and decide before writing.")
		return
	}
	b.ReviseCall(f.Tool, nil, "Fix the statement as the database's message says, then call again.")
}

// sanitizeIdent quotes a column name for the SQL a step suggests: in double
// quotes, a double quote doubled and a NUL dropped.
func sanitizeIdent(name string) string {
	name = strings.ReplaceAll(name, "\x00", "")
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
