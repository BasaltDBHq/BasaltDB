package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
)

// Reasons of the catalog (api/mcp/errors/next-steps.json) the engine sets
// itself, beyond the ones ToolError reads from the guard.
const (
	reasonHeld                = "HELD"
	reasonHeldNoPages         = "HELD_NO_PAGES"
	reasonNoPasskey           = "NO_PASSKEY"
	reasonWaitEnded           = "WAIT_ENDED"
	reasonNoRowsNow           = "NO_ROWS_NOW"
	reasonAlreadyUsed         = action.ReasonAlreadyUsed
	reasonDifferentWrite      = action.ReasonDifferentWrite
	reasonNotThisAgent        = action.ReasonNotThisAgent
	reasonLineInvalid         = action.ReasonLineInvalid
	reasonPlanNotSigned       = action.ReasonPlanNotSigned
	reasonDatabaseUnreachable = action.ReasonDatabaseUnreachable
	reasonTooManyConnections  = action.ReasonTooManyConnections
	reasonCredentialRejected  = action.ReasonCredentialRejected
	reasonGuardMissing        = action.ReasonGuardMissing
	reasonGuardOutdated       = "GUARD_OUTDATED"
	reasonEngineUnreachable   = "ENGINE_UNREACHABLE"
	reasonPagesOff            = "PAGES_OFF"
	reasonSetupPending        = "SETUP_PENDING"
	reasonSetupExpired        = "SETUP_EXPIRED"
	reasonRun                 = "RUN"
	reasonChange              = "CHANGE"
	reasonApproval            = "APPROVAL"
	reasonLink                = "LINK"
	reasonLinkReset           = "LINK_RESET"

	toolWrite         = "write"
	toolQuery         = "query"
	toolListPending   = "list_pending"
	toolRunHistory    = "run_history"
	toolPreviewRevert = "preview_revert"
	argRunID          = "runId"
	argApprovalID     = "approvalId"
	argChangeID       = "changeId"
	argWaitApproval   = "waitForApproval"
)

var catalog = sync.OnceValue(func() mcpcontract.NextSteps {
	c, err := mcpcontract.LoadNextSteps()
	if err != nil {
		panic(err) // the catalog is embedded: a failure is a build defect
	}
	return c
})

// failure is the call an error answers: the tool and its arguments.
type failure struct {
	tool string
	args map[string]any
	err  error
}

func (f failure) arg(name string) string {
	s, _ := f.args[name].(string)
	return s
}

// Failure maps err, raised by a call of tool with args, to the contract's
// error body (CONTRACT.md, Error codes and Next steps): code and reason,
// the message, the next steps and the person's message the catalog
// prescribes. Every tool error passes through it, so none reaches the agent
// bare. A body that already carries its steps (built where the engine
// knows the link or the ledger row) keeps them.
func (s *Service) Failure(tool string, args map[string]any, err error) *toolresult.ToolError {
	te := rowTooLargeFor(tool, messageTooLarge(tool, err, s.deps.Core.Errors.ToolError(err)))
	if te.Code == CodeInternal || te.Code == CodeUnavailable {
		if te.ErrorID == "" {
			te.ErrorID = uniqueid.New()
		}
		s.deps.Core.Log.Error("tool failed", "tool", tool, "code", te.Code, "reason", te.Reason, "error_id", te.ErrorID, "err", err)
	}
	s.addGuidance(te, failure{tool: tool, args: args, err: err})
	return te
}

// addGuidance fills te's next steps and person message from the catalog's
// entry for its code, reason and tool. A missing entry or a body that
// disagrees with it is a defect: it is logged here, and the catalog test
// fails on it.
func (s *Service) addGuidance(te *toolresult.ToolError, f failure) {
	entry, ok := catalog().ErrorEntry(te.Code, te.Reason, f.tool)
	if !ok {
		s.deps.Core.Log.Error("no catalog entry for the error", "code", te.Code, "reason", te.Reason, "tool", f.tool)
		return
	}
	if len(te.NextSteps) == 0 {
		steps, person, err := s.errorGuidance(te, f)
		if err != nil {
			s.deps.Core.Log.Error("cannot build next steps", "code", te.Code, "reason", te.Reason, "tool", f.tool, "err", err)
			return
		}
		te.NextSteps = steps
		if te.PersonMessage == "" {
			te.PersonMessage = fitToSteps(person, steps)
		}
	}
	if err := CheckPersonMessage(te.PersonMessage); err != nil {
		s.deps.Core.Log.Error("person message breaks its limit", "code", te.Code, "reason", te.Reason, "tool", f.tool, "err", err)
	}
	if entry.PersonMessage != (te.PersonMessage != "") {
		s.deps.Core.Log.Error("person message disagrees with the catalog", "code", te.Code, "reason", te.Reason, "tool", f.tool)
	}
}

// errorGuidance builds the steps and the person message for te, by code.
func (s *Service) errorGuidance(te *toolresult.ToolError, f failure) ([]toolresult.NextStep, string, error) {
	b, person := NewSteps(), ""
	switch te.Code {
	case CodeIntentRequired:
		b.ReviseCall(f.tool, nil, "Add an intent, one sentence saying why the change is made, then call write again.")
	case CodeStaleRead:
		s.staleReadSteps(b, te, f)
	case CodeStatementRefused:
		if te.Reason == ReasonHoldTooLarge {
			person = s.holdTooLargeSteps(b, te)
			break
		}
		person = refusedSteps(b, te, f)
	case CodeRowLimitExceeded:
		person = rowLimitSteps(b)
	case CodeQueryTimeout:
		queryTimeoutSteps(b, te, f)
	case CodeApprovalRequired:
		person = s.approvalRequiredSteps(b, te)
	case CodeApprovalExpired:
		approvalExpiredSteps(b)
		person = approvalExpiredMessage
	case CodeApprovalInvalid:
		person = approvalInvalidSteps(b, te, f)
	case CodeRevertInvalid:
		revertInvalidSteps(b, te, f)
	case CodePermissionDenied:
		person = s.permissionDeniedSteps(b, te, f)
	case CodeNotFound:
		if f.tool == toolDescribe {
			person = s.describeNotFoundSteps(b, f)
			break
		}
		person = notFoundSteps(b, te, f)
	case CodeSQLError:
		sqlErrorSteps(b, te, f)
	case CodeInvalidArgument:
		person = invalidArgumentSteps(b, te, f)
	case CodeUnavailable:
		person = s.unavailableSteps(b, te, f)
	case CodeInternal:
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
func (s *Service) staleReadSteps(b *Steps, te *toolresult.ToolError, f failure) {
	args, err := staleReadQuery(te.Message, f.arg(argRunID))
	if err != nil {
		// A detail the engine cannot read: the catalog's query step cannot be
		// filled in, so the agent stops and asks instead of guessing a row.
		s.deps.Core.Log.Error("stale read detail not understood", "err", err)
		b.Stop("Do not write on the old read, and do not retry the write as it is.")
		b.AskPerson("Tell the person the row changed since you read it, and ask how to go on.")
		return
	}
	b.CallTool(toolQuery, args, "Read the row again in this run, then decide.")
	b.ReviseCall(toolWrite, nil, "Decide again from what the row holds now, then send the write again with the same intent.")
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
	sort.Strings(cols)
	conds, params := make([]string, 0, len(cols)), make([]any, 0, len(cols))
	for i, c := range cols {
		conds = append(conds, fmt.Sprintf("%s = $%d", sanitizeIdent(c), i+1))
		params = append(params, key[c])
	}
	args := map[string]any{"sql": "SELECT * FROM " + m[1] + " WHERE " + strings.Join(conds, " AND "), "params": params}
	if runID != "" {
		args[argRunID] = runID
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
func refusedSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case string(action.ReasonDDL):
		b.Stop("Do not retry and do not look for another way to change the schema.")
		b.AskPerson("Tell the person which schema change you need; they make it themselves.")
		return "The agent tried to change the database schema (DDL). Basalt never lets an agent do that. Make the change yourself if you want it."
	case ReasonNoPrimaryKey:
		b.Stop("The table has no primary key, so its writes cannot be recorded: do not retry or work around it.")
		return fmt.Sprintf("%s has no primary key, so Basalt cannot guard writes to it and refuses them. Add a primary key to the table, "+
			"or revoke the agent's write access to it.", shown(tableFromDetail(te.Message), maxTableChars))
	case ReasonNotAllowed:
		b.Stop("The database refused this action for the agent: do not retry or work around it.")
		return ""
	}
	tool := f.tool
	if te.Reason == string(action.ReasonWrongTool) {
		tool = toolQuery // the statement went to write: it reads
		if f.tool == toolQuery {
			tool = toolWrite
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
func rowLimitSteps(b *Steps) string {
	b.Stop("Do not split the write to get around the limit, and do not retry it as it is.")
	b.AskPerson(fmt.Sprintf("Tell the person the write touches more than %d rows, cascades included, and ask whether to run it in held batches.", MaxRetryRows))
	b.RetrySmallerBatches(MaxRetryRows, fmt.Sprintf("Do this only on an explicit yes: write in batches of at most %d rows, same intent and run; the person approves each batch.", MaxRetryRows))
	return fmt.Sprintf("The agent's write touches more than %d rows (cascades included). It will ask you whether to run it in batches of up to %d rows; "+
		"you approve each batch with your passkey.", MaxRetryRows, MaxRetryRows)
}

// describeTimeoutText is the revision a describe that ran out of time asks
// for, by form: a narrower search, or a search in place of the whole
// overview or table.
func describeTimeoutText(f failure) string {
	switch {
	case f.arg(argQuery) != "":
		return "Search with a longer, more specific query so the catalog answers in time, then call describe again."
	case f.arg(argResource) != "":
		return "The catalog was slow: call describe for this table once more, or search with a query for the columns you need."
	}
	return "The catalog was slow: call describe once more, or search with a query for the tables you need."
}

func queryTimeoutSteps(b *Steps, te *toolresult.ToolError, f failure) {
	if f.tool == toolDescribe {
		b.ReviseCall(f.tool, nil, describeTimeoutText(f))
		return
	}
	switch te.Reason {
	case ReasonRowLimit:
		b.ReviseCall(f.tool, nil, "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.")
		return
	case ReasonSizeLimit:
		b.ReviseCall(f.tool, nil, sizeLimitText(f.tool))
		return
	case ReasonRowTooLarge:
		b.ReviseCall(f.tool, nil, "One row is too large to read whole: select fewer columns, the size of a large one "+
			"(length(col)) or a slice of it (substr(col, 1, 100000)), then call it again.")
		return
	}
	b.ReviseCall(f.tool, nil, "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again.")
}

// rowTooLargeTools are the tools whose own statement's rows the agent
// reads: query, and a write's RETURNING.
var rowTooLargeTools = map[string]bool{toolQuery: true, toolWrite: true}

// rowTooLargeFor keeps ROW_TOO_LARGE for the tools whose statement it
// refuses (CONTRACT.md, QUERY_TIMEOUT ROW_TOO_LARGE); any other tool's
// read too large for the budget is SIZE_LIMIT.
func rowTooLargeFor(tool string, te *toolresult.ToolError) *toolresult.ToolError {
	if te.Code == CodeQueryTimeout && te.Reason == ReasonRowTooLarge && !rowTooLargeTools[tool] {
		te = sizeLimitError()
	}
	if te.Code == CodeQueryTimeout && te.Reason == ReasonSizeLimit && pagedTools[tool] {
		// A paged tool's message names its step, not the columns of a query.
		te.Message = budget.ErrSizeLimit.Error() + "; call it again with a smaller limit, down to 1"
	}
	return te
}

// pagedTools page ledger items with limit: a smaller limit ends a
// SIZE_LIMIT (CONTRACT.md, Large values).
var pagedTools = map[string]bool{toolRunHistory: true, toolListPending: true, toolPreviewRevert: true, toolRevertPlan: true}

// sizeLimitText is what the agent revises after SIZE_LIMIT, by tool
// (CONTRACT.md, Next steps per code): a smaller page for the paged tools, a
// narrower revert for request_revert, fewer or shorter values otherwise.
func sizeLimitText(tool string) string {
	switch tool {
	case toolRunHistory, toolListPending, toolPreviewRevert, toolRevertPlan:
		return "Call it again with a smaller limit (half of it, for example) so the result stays under 16 MiB."
	case toolRequestRevert:
		return "Request a narrower revert, with runs or tables, so its lines stay under 16 MiB."
	}
	return "Select fewer or shorter columns (for example left(col, 200)) or fewer rows so the result stays under 16 MiB, then call it again."
}

func approvalExpiredSteps(b *Steps) {
	b.AskPerson("Tell the person the approval expired and the write stays blocked; ask whether to send it again.")
	b.ReviseCall(toolWrite, nil, "On yes, send the write again without approvalId, so it is held anew.")
}

func (s *Service) approvalRequiredSteps(b *Steps, te *toolresult.ToolError) string {
	n := te.Approval
	if n == nil {
		b.fail(fmt.Errorf("APPROVAL_REQUIRED carries no approval"))
		return ""
	}
	again := map[string]any{argApprovalID: n.ApprovalID}
	b.SendRequest(n.RequestFile)
	switch te.Reason {
	case reasonHeld:
		b.OpenLink(n.ApprovalURL, "Open the link, review the rows and approve with your passkey.")
		b.RepeatCall(toolWrite, again, 0, fmt.Sprintf("In this turn, call write again with the same arguments plus approvalId: it waits up to %d seconds for the approval.", int(DefaultApprovalWait.Seconds())))
	case reasonHeldNoPages:
		// No page can sign this link (no local pages, no live Vault
		// connection): a wait cannot succeed.
		b.OpenLink(n.ApprovalURL, "Open the link to review the rows. It cannot be signed yet.")
		b.EndTurn("Do not wait: this link cannot be signed. End your turn, showing approval.personMessage.")
		b.CallTool(toolListPending, map[string]any{argReissueLink: true}, "Once status shows the Vault connected, call this for a link the person can sign, and show it.")
	case reasonNoPasskey:
		b.AgentRunCommand(s.deps.Core.Commands.Init(), "Nobody can approve yet: run this once and show the person the link it prints, where they register a passkey.")
		if s.deps.Core.Commands.AgentOperated() {
			// The person registers a portal passkey on the connect page,
			// and the agent follows what init prints (RI-6).
			break
		}
		b.OpenLink(n.ApprovalURL, "Then open the link and approve the held write.")
		b.EndTurn("End your turn: the person acts next.")
	case reasonWaitEnded:
		s.openHeldLink(b, n, "Open the link to review the rows. It cannot be signed yet: ask the agent for a new link later.")
		b.TellAgent("Tell the agent when you have approved.")
		b.EndTurn("Do not wait again: end your turn, showing personMessage.")
		b.RepeatCall(toolWrite, map[string]any{argApprovalID: n.ApprovalID, argWaitApproval: 0}, 0,
			"When the person says they approved, call write again with the same arguments plus approvalId: it applies at once.")
	}
	return n.PersonMessage
}

// approvalInvalidSteps: what the agent does depends on why the guard
// refused the approval. The three that need the approval page (NOT_SIGNED,
// BAD_SIGNATURE, PASSKEY_REVOKED) are built with its link by
// approvalLinkError.
func approvalInvalidSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case reasonAlreadyUsed:
		b.CallTool(toolRunHistory, runArgs(f), "Read the run's history: the write was already applied.")
		b.Stop("Do not apply it again.")
	case reasonDifferentWrite:
		b.CallTool(toolListPending, runArgs(f), "List the held write, then send exactly its sql, params and intent with its approvalId.")
	case reasonNotThisAgent:
		b.CallTool(toolListPending, map[string]any{}, "List your pending approvals and use the approvalId of the one this write was held for.")
	case reasonRowsChanged:
		b.ReviseCall(toolQuery, nil, "Read the rows again to see what changed since the person was asked.")
		b.ReviseCall(toolWrite, nil, "Send the write again with the new rows in mind: it is held anew for approval.")
		return "Rows changed after you were asked, so that approval no longer applies and nothing was written. The agent reads the rows again and the write is held anew for you."
	default:
		b.fail(fmt.Errorf("APPROVAL_INVALID %s needs the approval page's link", te.Reason))
	}
	return ""
}

func runArgs(f failure) map[string]any {
	if id := f.arg(argRunID); id != "" {
		return map[string]any{argRunID: id}
	}
	return map[string]any{}
}

func revertInvalidSteps(b *Steps, te *toolresult.ToolError, f failure) {
	id := f.arg(argRevertID)
	switch te.Reason {
	case reasonLineInvalid:
		b.CallTool(toolRevertPlan, map[string]any{argRevertID: id, "pending": true}, "Read the plan's pending lines again and send only those.")
	case reasonPlanNotSigned:
		b.CallTool(toolRevertPlan, map[string]any{argRevertID: id}, "Read the plan: it is not signed yet.")
		b.EndTurn("The person signs the plan on the revert page; end your turn and apply it when they say they signed.")
	case reasonPlanFinished:
		b.CallTool(toolRevertPlan, map[string]any{argRevertID: id}, "Read the plan's final state.")
		b.Stop("The revert is applied: do not send more lines.")
	case reasonNotThisAgent:
		b.Stop("This revert is not one of yours: do not retry.")
	default:
		b.fail(fmt.Errorf("REVERT_INVALID %s needs the revert page's link", te.Reason))
	}
}

var deniedTable = regexp.MustCompile(`permission denied for (?:table|relation) (\S+)`)

// permissionDeniedSteps: the agent asks, and only when the person tells it
// to add the access, in a later turn, runs basalt init, whose link opens the
// page where the person grants it (RI-16). The message names the table
// Postgres named, never a command.
func (s *Service) permissionDeniedSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	b.Stop("The agent role may not do this: do not retry or look for another route.")
	access := "write"
	if f.tool == toolQuery {
		access = "read"
	}
	what := "access to what it asked for"
	if m := deniedTable.FindStringSubmatch(te.Message); m != nil {
		what = access + " access to " + shown(m[1], maxTableChars)
	}
	b.AskPerson("Tell the person which access is missing and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the access once you decide it should have it.")
	b.EndTurn("End your turn: the person decides.")
	b.AgentRunCommand(s.deps.Core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the access.")
	return fmt.Sprintf("The agent was denied %s. If it should have it, tell the agent: it gives you a link where you grant it.", what)
}

func notFoundSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case reasonRun:
		b.CallTool(toolListRuns, map[string]any{}, "List your runs, or start a new one with run_start.")
	case reasonChange:
		if id := f.arg(argRunID); id != "" {
			b.CallTool(toolRunHistory, map[string]any{argRunID: id}, "Read the run's history to find the id of the change you mean.")
			return ""
		}
		b.CallTool(toolListRuns, map[string]any{}, "List your runs, then read one run's history for the change id.")
	case reasonApproval:
		b.CallTool(toolListPending, map[string]any{}, "List your pending approvals to find the right approvalId.")
	case reasonRevert:
		b.AskPerson("Ask the person which revert they mean; this agent prepared no revert with that id.")
	case reasonLink:
		b.TellAgent("Ask the agent for the link again.")
		return "This link is incomplete, expired or was replaced by a newer one. Ask the agent for the link again."
	case reasonLinkReset:
		b.TellAgent("Ask the agent for the new link to this revert.")
		return linkResetMessage
	default:
		b.fail(fmt.Errorf("NOT_FOUND has no reason %q", te.Reason))
	}
	return ""
}

func sqlErrorSteps(b *Steps, te *toolresult.ToolError, f failure) {
	if te.Reason == reasonNoRowsNow {
		b.ReviseCall(f.tool, nil, "The write now changes no rows: read the rows again with query and decide before writing.")
		return
	}
	b.ReviseCall(f.tool, nil, "Fix the statement as the database's message says, then call again.")
}

func invalidArgumentSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case ReasonStaleCursor:
		b.RepeatCall(f.tool, map[string]any{"cursor": nil}, 0, "The cursor is no longer valid: call again without cursor to start from the first page.")
		return ""
	case ReasonScopeFilter:
		b.ReviseCall(f.tool, nil, "Call again without the refused entries the message names, or without that filter.")
		if id := f.arg(argRunID); id != "" {
			b.CallTool(toolRunHistory, map[string]any{argRunID: id}, "Read the run's history to see the tables you wrote in it.")
			return ""
		}
		b.CallTool(toolListRuns, map[string]any{}, "List your runs to see your own runs in the task; run_history shows the tables each one wrote.")
		return ""
	case ReasonScopeFilterCap:
		b.ReviseCall(f.tool, nil, fmt.Sprintf("Call again with at most %d runs and %d tables, or without the filter: the person "+
			"can narrow it on the signing page.", revert.MaxFilter, revert.MaxFilter))
		return ""
	case ReasonAdminCredential:
		b.AskPerson(adminCredentialAsk)
		b.ReviseCall(f.tool, nil, adminCredentialRevise)
		return adminCredentialPerson
	}
	b.ReviseCall(f.tool, nil, "Fix the arguments as the message says; the tool's input schema lists them.")
	return ""
}

// unavailableSteps: a database the engine cannot reach is retried once; the
// machine problems are the person's to fix, with the command for it.
func (s *Service) unavailableSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case reasonDatabaseUnreachable:
		b.RepeatCall(f.tool, nil, 0, "Try the same call once more, in case the database was only briefly busy.")
		b.AskPerson("Then tell the person the database cannot be reached and ask them to check that Postgres is running.")
		return databaseUnreachableMessage
	case reasonTooManyConnections:
		b.RepeatCall(f.tool, nil, 0, "Try the same call once more: a connection may have closed since.")
		b.AskPerson(tooManyConnectionsAsk)
		return tooManyConnectionsMessage(s.deps.Core.Commands)
	case reasonCredentialRejected, reasonGuardMissing, reasonGuardOutdated:
		return fixSteps(b, s.deps.Core.Commands, te.Reason)
	case reasonEngineUnreachable:
		return engineUnreachableSteps(b, s.deps.Core.Commands, f.tool)
	case reasonSetupPending, reasonSetupExpired:
		return s.setupSteps(b, te, f)
	case reasonDatabaseNotConfirmed:
		var dn *DatabaseNotConfirmedError
		if !errors.As(f.err, &dn) {
			b.fail(errors.New("a database waiting for confirmation needs its setup and address"))
			return ""
		}
		return confirmDatabaseSteps(b, dn.SetupID, dn.Database)
	case reasonPagesOff:
		b.CallTool(toolListPending, map[string]any{}, "Read the held writes: each has the link the person opens, since this engine serves no pages.")
		return ""
	}
	b.fail(fmt.Errorf("UNAVAILABLE has no reason %q", te.Reason))
	return ""
}

// databaseUnreachableMessage is the person's message when the database
// cannot be reached, in an error and in status.
const databaseUnreachableMessage = "The agent cannot reach the database. Check that Postgres is running and reachable from the machine the engine runs on."

// tooManyConnectionsAsk is the ASK_PERSON step when the agent role is at its
// connection limit, in an error and in status.
const tooManyConnectionsAsk = "Tell the person the agent has used all the database connections Basalt allows it, and ask them to stop any second engine for this agent."

// tooManyConnectionsMessage is the person's message when the agent role is at
// its connection limit, in an error and in status (CONTRACT.md, Error codes).
func tooManyConnectionsMessage(cmds Commands) string {
	return fmt.Sprintf("The agent %s has used all %d database connections Basalt allows it. "+
		"Another engine for the same agent may be running, or a stopped engine left sessions open. "+
		"Stop any second engine; stale sessions close on their own within a few minutes.",
		cmds.agent, guardmodel.AgentConnectionLimit)
}

// fixes are what the person is told for the machine problems of the guard
// and the credential, shared by the UNAVAILABLE errors and the status
// problems of the same name. basalt init fixes each: its link opens the
// setup page, or the connect page on an agent-operated engine, for that job.
var fixes = map[string]string{
	reasonCredentialRejected: "The database refuses the agent's credential (its password changed or was never right), so the agent needs a new one.",
	reasonGuardMissing:       "Basalt's guard is not installed in this database (or was removed), so the agent cannot work.",
	reasonGuardOutdated:      "Basalt's guard in this database is older than this engine needs, so the agent cannot work until it is updated.",
}

// fixSteps: the agent runs basalt init, whose link the person opens to fix
// reason; the person tells the agent when it is done and the agent stops
// until then. On an agent-operated engine the agent follows what init
// prints instead (RI-17 for CREDENTIAL_REJECTED).
func fixSteps(b *Steps, cmds Commands, reason string) string {
	problem, ok := fixes[reason]
	if !ok {
		b.fail(fmt.Errorf("no fix for %s", reason))
		return ""
	}
	if cmds.AgentOperated() {
		return remoteSetupSteps(b, cmds, problem)
	}
	if cmds.engineRemoved() {
		// The setup page removed BasaltDB and the engine's last agent: its
		// role is gone, so every call fails. basalt init finishes the
		// removal (CONTRACT.md, The local setup page, Removing the engine
		// service).
		b.AgentRunCommand(cmds.Init(), removedInitText)
		b.TellAgent("Tell the agent when it is done.")
		b.Stop("Do not retry: BasaltDB is removed from this database.")
		return removedPersonText
	}
	if reason == reasonGuardOutdated && cmds.updateLink != "" {
		b.OpenLink(cmds.updateLink, "Show the person this link: its page updates the guard once they type the admin connection string there.")
		b.TellAgent("Tell the agent when it is done.")
		b.Stop("Do not retry until the person says it is fixed.")
		return problem + " Open the link the agent gives you, follow the page, then tell the agent."
	}
	b.AgentRunCommand(cmds.Init(), initStepText)
	b.TellAgent("Tell the agent when it is done.")
	b.Stop("Do not retry until the person says it is fixed.")
	return problem + " " + initPersonText
}

// removedInitText and removedPersonText are the fix steps' texts on an
// engine the setup page removed.
const (
	removedInitText   = "BasaltDB is removed from this database. Run this once to finish: it removes the engine service, and the person types their password once in the computer's own dialog."
	removedPersonText = "BasaltDB is removed from this database. Last step: the agent runs basalt init once, and your computer asks for your password once to remove the engine service."
)

// initStepText is the text of the agent's basalt init step: it prints the
// one link the person opens (CONTRACT.md, basalt init).
const initStepText = "Run this once and show the person the link it prints; they fix it on that page."

// passkeyInitText is the text of the agent's basalt init step for a passkey
// the database does not accept.
const passkeyInitText = "Run this once and show the person the link it prints, where they register the passkey they use."

// askAgentForRegisterLinkText is a page's step for a passkey the database does not
// accept: the page cannot run basalt init, so the person asks the agent.
const askAgentForRegisterLinkText = "Ask the agent for a link to register the passkey you use."

// initPersonText tells the person what follows the agent's basalt init.
const initPersonText = "The agent gives you a link: open it, follow the page, then tell the agent."

// remoteSetupSteps: on an agent-operated engine, the agent runs basalt init
// now; what it prints (the connect link, its personMessage and nextSteps)
// replaces the rest of these steps (RI-2). The person's message names no
// command on the agent's machine.
func remoteSetupSteps(b *Steps, cmds Commands, problem string) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the link it prints and follow its steps.")
	return problem + " " + initPersonText
}

// engineUnreachableSteps: the person starts the engine; on an agent-operated
// engine the agent starts it, once, then repeats tool (status when tool is
// empty or status itself).
func engineUnreachableSteps(b *Steps, cmds Commands, tool string) string {
	if !cmds.AgentOperated() {
		return personFix(b, cmds.EngineStart(), "The agent cannot reach the engine, so it is not running.")
	}
	b.AgentRunCommand(cmds.EngineStart(), "Start the Basalt engine on this machine, once; ask the person when it still does not answer.")
	if tool == "" || tool == toolStatus {
		b.CallTool(toolStatus, map[string]any{}, "Then call status to check that the engine answers.")
		return ""
	}
	b.RepeatCall(tool, nil, 0, "Then make the same call again, once.")
	return ""
}

func personFix(b *Steps, command, problem string) string {
	b.RunCommand(command, "Run this to fix it.")
	b.TellAgent("Tell the agent when it is done.")
	b.Stop("Do not retry until the person says it is fixed.")
	return fmt.Sprintf("%s Run: %s then tell the agent.", problem, command)
}

// approvalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page: not signed yet, a signature the
// database refused, or a passkey it does not accept. The link in its message
// follows the link budget like the hold's; no new short link is issued here.
func (s *Service) approvalLinkError(te *toolresult.ToolError, n heldNotice) *toolresult.ToolError {
	if n.reason == reasonRequestTooLarge {
		// No link can carry it: the same message and steps as the hold's.
		te.PersonMessage, te.NextSteps = n.PersonMessage, n.steps
		return te
	}
	b := NewSteps()
	var lead string
	switch te.Reason {
	case reasonNotSigned:
		s.openApprovalAgain(b, n, "Open the link and approve with your passkey: the write is not approved yet.")
		lead = "The held write was not approved yet, so nothing was applied."
	case reasonBadSignature:
		s.openApprovalAgain(b, n, "Approve again on the page; the signature did not verify.")
		lead = "The approval signature did not verify, so nothing was applied."
	case reasonPasskeyRevoked:
		b.AgentRunCommand(s.deps.Core.Commands.Init(), passkeyInitText)
		s.openApprovalAgain(b, n, "Then approve the held write with that passkey.")
		lead = "That passkey is not accepted here (unknown or revoked), so nothing was applied. The agent gives you a link to register the passkey you use; then approve again."
	default:
		return te
	}
	te.PersonMessage, te.Links = s.approvalAgainMessage(lead, n)
	b.EndTurn("End your turn: the person acts next.")
	steps, err := b.Build()
	if err != nil {
		s.deps.Core.Log.Error("cannot build approval steps", "reason", te.Reason, "err", err)
		return te
	}
	te.NextSteps = steps
	return te
}

// openApprovalAgain sends the person back to the approval page the hold
// handed over. With the pages served that is the short link they have, which
// the engine no longer holds: the step names no url, and no long link over
// the budget is handed over (CONTRACT.md, The request file and pasted
// blocks). Otherwise it is the link the hold chose: the long link within the
// budget, or the hash link, whose request file the agent already sent.
func (s *Service) openApprovalAgain(b *Steps, n heldNotice, text string) {
	if n.shortHeld || isPageAddress(n.ApprovalURL) {
		b.OpenGivenLink("Open the short link the agent gave you earlier. " + text)
		return
	}
	b.OpenLink(n.ApprovalURL, text)
}

// approvalAgainMessage is the personMessage of an APPROVAL_INVALID that sends
// the person back to the page: a pointer to the short link they have while
// the pages are served, else the hold's link (a hash link names the request
// file the agent already sent).
func (s *Service) approvalAgainMessage(lead string, n heldNotice) (string, []toolresult.Link) {
	if n.shortHeld {
		return pointBackMessage(lead)
	}
	return approvalMessage(lead, handOver{URL: n.pick.URL, Kind: n.pick.Kind, File: n.pick.File, sent: true})
}

// SetupError is a call refused because the agent's setup from the laptop has
// not run (CONTRACT.md, Setup from your laptop). Code is the pending setup
// code, which the person runs on their own computer, and Fingerprint the
// one it shows; Expired when it ran out.
type SetupError struct {
	Code        string
	Fingerprint string
	Expired     bool
	// ConnectOnly: the pending code is connect-only, so status's setup
	// problem says what comes next (CONTRACT.md, Next steps for a
	// connect-only code).
	ConnectOnly bool
}

func (e *SetupError) Error() string {
	if e.Expired {
		return "the agent's setup code expired before it was used"
	}
	return "the agent's setup has not run yet"
}

// setupCode is a setup code's alphabet: basalt-setup.1.<base64url>.<check>.
var setupCode = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// setupSteps: a pending setup is run by the person on their own computer;
// an expired one is renewed on the engine's machine (an OPERATOR step).
func (s *Service) setupSteps(b *Steps, te *toolresult.ToolError, f failure) string {
	if te.Reason == reasonSetupExpired {
		return setupExpiredSteps(b, s.deps.Core.Commands)
	}
	var se *SetupError
	if !errors.As(f.err, &se) {
		b.fail(errors.New("a pending setup needs its code"))
		return ""
	}
	if se.ConnectOnly {
		b.CallTool(toolStatus, map[string]any{}, "Call status: its setup problem says what the person or you do next.")
		return ""
	}
	person, ls := setupPendingSteps(b, s.deps.Core.Commands, se.Code, se.Fingerprint, true, s.deps.Status.ConnectBudget)
	te.Links = ls
	return person
}

// setupExpiredSteps: the agent runs basalt init again for a new link.
func setupExpiredSteps(b *Steps, cmds Commands) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The setup link for this agent expired before it was used. " + initPersonText
}

// setupPendingSteps: the person finishes the pending setup on the connect
// page, checking it shows fingerprint. An INSTALL code blocks the tools
// (blocking), so the agent ends its turn and checks status after; an AGENT
// or UPGRADE code does not.
//
// With a connect link (budget is not 0 and the whole link fits it) the
// person opens it, and the message says the link uses Basalt Vault, a
// hosted service (CONTRACT.md, Next steps with the connect link). Without
// one there is no page to hand over: the agent runs basalt init, which
// prints the link. The links are those of the message.
func setupPendingSteps(b *Steps, cmds Commands, code, fingerprint string, blocking bool, budget int) (string, []toolresult.Link) {
	if !setupCode.MatchString(code) || fingerprint == "" {
		b.fail(errors.New("a pending setup needs its code and fingerprint"))
		return "", nil
	}
	url := ConnectLink(code, budget)
	if url != "" {
		b.OpenLink(url, ConnectStepText)
	} else {
		b.AgentRunCommand(cmds.Init(), "Run this once and show the person the link it prints, where they finish the setup.")
	}
	b.TellAgent("Tell the agent when it is done.")
	lead := "A change to this agent's setup is waiting for you."
	if blocking {
		b.EndTurn("End your turn: the person acts next.")
		b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
		lead = "This agent's setup has not run yet."
	}
	if url != "" {
		return ConnectMessage(lead, url, fingerprint)
	}
	return lead + " The agent gives you a link: open it, check that it shows the setup fingerprint " + fingerprint +
		", and follow the page, then tell the agent. Never paste your database password into this chat.", nil
}

// sanitizeIdent quotes a column name for the SQL a step suggests: in double
// quotes, a double quote doubled and a NUL dropped.
func sanitizeIdent(name string) string {
	name = strings.ReplaceAll(name, "\x00", "")
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
