package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
)

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
	te := rowTooLargeFor(tool, guidance.MessageTooLarge(tool, err, s.deps.Core.Errors.ToolError(err)))
	if te.Code == guidance.CodeInternal || te.Code == guidance.CodeUnavailable {
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
	entry, ok := guidance.Catalog().ErrorEntry(te.Code, te.Reason, f.tool)
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
			te.PersonMessage = guidance.FitToSteps(person, steps)
		}
	}
	if err := guidance.CheckPersonMessage(te.PersonMessage); err != nil {
		s.deps.Core.Log.Error("person message breaks its limit", "code", te.Code, "reason", te.Reason, "tool", f.tool, "err", err)
	}
	if entry.PersonMessage != (te.PersonMessage != "") {
		s.deps.Core.Log.Error("person message disagrees with the catalog", "code", te.Code, "reason", te.Reason, "tool", f.tool)
	}
}

// errorGuidance builds the steps and the person message for te, by code.
func (s *Service) errorGuidance(te *toolresult.ToolError, f failure) ([]toolresult.NextStep, string, error) {
	b, person := guidance.NewSteps(), ""
	switch te.Code {
	case guidance.CodeIntentRequired:
		b.ReviseCall(f.tool, nil, "Add an intent, one sentence saying why the change is made, then call write again.")
	case guidance.CodeStaleRead:
		s.staleReadSteps(b, te, f)
	case guidance.CodeStatementRefused:
		if te.Reason == action.ReasonHoldTooLarge {
			person = s.approval.holdTooLargeSteps(b, te)
			break
		}
		person = refusedSteps(b, te, f)
	case guidance.CodeRowLimitExceeded:
		person = rowLimitSteps(b)
	case guidance.CodeQueryTimeout:
		queryTimeoutSteps(b, te, f)
	case guidance.CodeApprovalRequired:
		person = s.approvalRequiredSteps(b, te)
	case guidance.CodeApprovalExpired:
		guidance.ApprovalExpiredSteps(b)
		person = approvalExpiredMessage
	case guidance.CodeApprovalInvalid:
		person = approvalInvalidSteps(b, te, f)
	case guidance.CodeRevertInvalid:
		revertInvalidSteps(b, te, f)
	case guidance.CodePermissionDenied:
		person = s.permissionDeniedSteps(b, te, f)
	case guidance.CodeNotFound:
		if f.tool == toolDescribe {
			person = s.describe.describeNotFoundSteps(b, f)
			break
		}
		person = notFoundSteps(b, te, f)
	case guidance.CodeSQLError:
		sqlErrorSteps(b, te, f)
	case guidance.CodeInvalidArgument:
		person = invalidArgumentSteps(b, te, f)
	case guidance.CodeUnavailable:
		person = s.unavailableSteps(b, te, f)
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
func (s *Service) staleReadSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) {
	args, err := staleReadQuery(te.Message, f.arg(guidance.ArgRunID))
	if err != nil {
		// A detail the engine cannot read: the catalog's query step cannot be
		// filled in, so the agent stops and asks instead of guessing a row.
		s.deps.Core.Log.Error("stale read detail not understood", "err", err)
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
	sort.Strings(cols)
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
func refusedSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case string(action.ReasonDDL):
		b.Stop("Do not retry and do not look for another way to change the schema.")
		b.AskPerson("Tell the person which schema change you need; they make it themselves.")
		return "The agent tried to change the database schema (DDL). Basalt never lets an agent do that. Make the change yourself if you want it."
	case guidance.ReasonNoPrimaryKey:
		b.Stop("The table has no primary key, so its writes cannot be recorded: do not retry or work around it.")
		return fmt.Sprintf("%s has no primary key, so Basalt cannot guard writes to it and refuses them. Add a primary key to the table, "+
			"or revoke the agent's write access to it.", guidance.Shown(tableFromDetail(te.Message), maxTableChars))
	case guidance.ReasonNotAllowed:
		b.Stop("The database refused this action for the agent: do not retry or work around it.")
		return ""
	}
	tool := f.tool
	if te.Reason == string(action.ReasonWrongTool) {
		tool = guidance.ToolQuery // the statement went to write: it reads
		if f.tool == guidance.ToolQuery {
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

func queryTimeoutSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) {
	if f.tool == toolDescribe {
		b.ReviseCall(f.tool, nil, describeTimeoutText(f))
		return
	}
	switch te.Reason {
	case guidance.ReasonRowLimit:
		b.ReviseCall(f.tool, nil, "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.")
		return
	case guidance.ReasonSizeLimit:
		b.ReviseCall(f.tool, nil, sizeLimitText(f.tool))
		return
	case guidance.ReasonRowTooLarge:
		b.ReviseCall(f.tool, nil, "One row is too large to read whole: select fewer columns, the size of a large one "+
			"(length(col)) or a slice of it (substr(col, 1, 100000)), then call it again.")
		return
	}
	b.ReviseCall(f.tool, nil, "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again.")
}

// rowTooLargeTools are the tools whose own statement's rows the agent
// reads: query, and a write's RETURNING.
var rowTooLargeTools = map[string]bool{guidance.ToolQuery: true, guidance.ToolWrite: true}

// rowTooLargeFor keeps ROW_TOO_LARGE for the tools whose statement it
// refuses (CONTRACT.md, QUERY_TIMEOUT ROW_TOO_LARGE); any other tool's
// read too large for the budget is SIZE_LIMIT.
func rowTooLargeFor(tool string, te *toolresult.ToolError) *toolresult.ToolError {
	if te.Code == guidance.CodeQueryTimeout && te.Reason == guidance.ReasonRowTooLarge && !rowTooLargeTools[tool] {
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

func (s *Service) approvalRequiredSteps(b *guidance.Steps, te *toolresult.ToolError) string {
	n := te.Approval
	if n == nil {
		b.Fail(fmt.Errorf("APPROVAL_REQUIRED carries no approval"))
		return ""
	}
	again := map[string]any{guidance.ArgApprovalID: n.ApprovalID}
	b.SendRequest(n.RequestFile)
	switch te.Reason {
	case guidance.ReasonHeld:
		b.OpenLink(n.ApprovalURL, "Open the link, review the rows and approve with your passkey.")
		b.RepeatCall(guidance.ToolWrite, again, 0, fmt.Sprintf("In this turn, call write again with the same arguments plus approvalId: it waits up to %d seconds for the approval.", int(DefaultApprovalWait.Seconds())))
	case guidance.ReasonHeldNoPages:
		// No page can sign this link (no local pages, no live Vault
		// connection): a wait cannot succeed.
		b.OpenLink(n.ApprovalURL, "Open the link to review the rows. It cannot be signed yet.")
		b.EndTurn("Do not wait: this link cannot be signed. End your turn, showing approval.personMessage.")
		b.CallTool(guidance.ToolListPending, map[string]any{ArgReissueLink: true}, "Once status shows the Vault connected, call this for a link the person can sign, and show it.")
	case guidance.ReasonNoPasskey:
		b.AgentRunCommand(s.deps.Core.Commands.Init(), "Nobody can approve yet: run this once and show the person the link it prints, where they register a passkey.")
		if s.deps.Core.Commands.AgentOperated() {
			// The person registers a portal passkey on the connect page,
			// and the agent follows what init prints (RI-6).
			break
		}
		b.OpenLink(n.ApprovalURL, "Then open the link and approve the held write.")
		b.EndTurn("End your turn: the person acts next.")
	case guidance.ReasonWaitEnded:
		s.approval.openHeldLink(b, n, "Open the link to review the rows. It cannot be signed yet: ask the agent for a new link later.")
		b.TellAgent("Tell the agent when you have approved.")
		b.EndTurn("Do not wait again: end your turn, showing personMessage.")
		b.RepeatCall(guidance.ToolWrite, map[string]any{guidance.ArgApprovalID: n.ApprovalID, guidance.ArgWaitApproval: 0}, 0,
			"When the person says they approved, call write again with the same arguments plus approvalId: it applies at once.")
	}
	return n.PersonMessage
}

// approvalInvalidSteps: what the agent does depends on why the guard
// refused the approval. The three that need the approval page (NOT_SIGNED,
// BAD_SIGNATURE, PASSKEY_REVOKED) are built with its link by
// approvalLinkError.
func approvalInvalidSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case guidance.ReasonAlreadyUsed:
		b.CallTool(guidance.ToolRunHistory, runArgs(f), "Read the run's history: the write was already applied.")
		b.Stop("Do not apply it again.")
	case guidance.ReasonDifferentWrite:
		b.CallTool(guidance.ToolListPending, runArgs(f), "List the held write, then send exactly its sql, params and intent with its approvalId.")
	case guidance.ReasonNotThisAgent:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "List your pending approvals and use the approvalId of the one this write was held for.")
	case guidance.ReasonRowsChanged:
		b.ReviseCall(guidance.ToolQuery, nil, "Read the rows again to see what changed since the person was asked.")
		b.ReviseCall(guidance.ToolWrite, nil, "Send the write again with the new rows in mind: it is held anew for approval.")
		return "Rows changed after you were asked, so that approval no longer applies and nothing was written. The agent reads the rows again and the write is held anew for you."
	default:
		b.Fail(fmt.Errorf("APPROVAL_INVALID %s needs the approval page's link", te.Reason))
	}
	return ""
}

func runArgs(f failure) map[string]any {
	if id := f.arg(guidance.ArgRunID); id != "" {
		return map[string]any{guidance.ArgRunID: id}
	}
	return map[string]any{}
}

func revertInvalidSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) {
	id := f.arg(guidance.ArgRevertID)
	switch te.Reason {
	case guidance.ReasonLineInvalid:
		b.CallTool(guidance.ToolRevertPlan, map[string]any{guidance.ArgRevertID: id, "pending": true}, "Read the plan's pending lines again and send only those.")
	case guidance.ReasonPlanNotSigned:
		b.CallTool(guidance.ToolRevertPlan, map[string]any{guidance.ArgRevertID: id}, "Read the plan: it is not signed yet.")
		b.EndTurn("The person signs the plan on the revert page; end your turn and apply it when they say they signed.")
	case guidance.ReasonPlanFinished:
		b.CallTool(guidance.ToolRevertPlan, map[string]any{guidance.ArgRevertID: id}, "Read the plan's final state.")
		b.Stop("The revert is applied: do not send more lines.")
	case guidance.ReasonNotThisAgent:
		b.Stop("This revert is not one of yours: do not retry.")
	default:
		b.Fail(fmt.Errorf("REVERT_INVALID %s needs the revert page's link", te.Reason))
	}
}

var deniedTable = regexp.MustCompile(`permission denied for (?:table|relation) (\S+)`)

// permissionDeniedSteps: the agent asks, and only when the person tells it
// to add the access, in a later turn, runs basalt init, whose link opens the
// page where the person grants it (RI-16). The message names the table
// Postgres named, never a command.
func (s *Service) permissionDeniedSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	b.Stop("The agent role may not do this: do not retry or look for another route.")
	access := "write"
	if f.tool == guidance.ToolQuery {
		access = "read"
	}
	what := "access to what it asked for"
	if m := deniedTable.FindStringSubmatch(te.Message); m != nil {
		what = access + " access to " + guidance.Shown(m[1], maxTableChars)
	}
	b.AskPerson("Tell the person which access is missing and ask whether you should have it.")
	b.TellAgent("Tell the agent to add the access once you decide it should have it.")
	b.EndTurn("End your turn: the person decides.")
	b.AgentRunCommand(s.deps.Core.Commands.Init(), "When the person tells you to add it, run this and show them the link it prints, where they grant the access.")
	return fmt.Sprintf("The agent was denied %s. If it should have it, tell the agent: it gives you a link where you grant it.", what)
}

func notFoundSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case guidance.ReasonRun:
		b.CallTool(guidance.ToolListRuns, map[string]any{}, "List your runs, or start a new one with run_start.")
	case guidance.ReasonChange:
		if id := f.arg(guidance.ArgRunID); id != "" {
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
		return LinkResetMessage
	default:
		b.Fail(fmt.Errorf("NOT_FOUND has no reason %q", te.Reason))
	}
	return ""
}

func sqlErrorSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) {
	if te.Reason == guidance.ReasonNoRowsNow {
		b.ReviseCall(f.tool, nil, "The write now changes no rows: read the rows again with query and decide before writing.")
		return
	}
	b.ReviseCall(f.tool, nil, "Fix the statement as the database's message says, then call again.")
}

func invalidArgumentSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case guidance.ReasonStaleCursor:
		b.RepeatCall(f.tool, map[string]any{"cursor": nil}, 0, "The cursor is no longer valid: call again without cursor to start from the first page.")
		return ""
	case guidance.ReasonScopeFilter:
		b.ReviseCall(f.tool, nil, "Call again without the refused entries the message names, or without that filter.")
		if id := f.arg(guidance.ArgRunID); id != "" {
			b.CallTool(guidance.ToolRunHistory, map[string]any{guidance.ArgRunID: id}, "Read the run's history to see the tables you wrote in it.")
			return ""
		}
		b.CallTool(guidance.ToolListRuns, map[string]any{}, "List your runs to see your own runs in the task; run_history shows the tables each one wrote.")
		return ""
	case guidance.ReasonScopeFilterCap:
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
func (s *Service) unavailableSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	switch te.Reason {
	case guidance.ReasonDatabaseUnreachable:
		b.RepeatCall(f.tool, nil, 0, "Try the same call once more, in case the database was only briefly busy.")
		b.AskPerson("Then tell the person the database cannot be reached and ask them to check that Postgres is running.")
		return guidance.DatabaseUnreachableMessage
	case guidance.ReasonTooManyConnections:
		b.RepeatCall(f.tool, nil, 0, "Try the same call once more: a connection may have closed since.")
		b.AskPerson(guidance.TooManyConnectionsAsk)
		return guidance.TooManyConnectionsMessage(s.deps.Core.Commands)
	case guidance.ReasonCredentialRejected, guidance.ReasonGuardMissing, guidance.ReasonGuardOutdated:
		return guidance.FixSteps(b, s.deps.Core.Commands, te.Reason)
	case guidance.ReasonEngineUnreachable:
		return guidance.EngineUnreachableSteps(b, s.deps.Core.Commands, f.tool)
	case guidance.ReasonSetupPending, guidance.ReasonSetupExpired:
		return s.setupSteps(b, te, f)
	case guidance.ReasonDatabaseNotConfirmed:
		var dn *guidance.DatabaseNotConfirmedError
		if !errors.As(f.err, &dn) {
			b.Fail(errors.New("a database waiting for confirmation needs its setup and address"))
			return ""
		}
		return confirmDatabaseSteps(b, dn.SetupID, dn.Database)
	case guidance.ReasonPagesOff:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "Read the held writes: each has the link the person opens, since this engine serves no pages.")
		return ""
	}
	b.Fail(fmt.Errorf("UNAVAILABLE has no reason %q", te.Reason))
	return ""
}

// approvalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page: not signed yet, a signature the
// database refused, or a passkey it does not accept. The link in its message
// follows the link budget like the hold's; no new short link is issued here.
func (s *Service) approvalLinkError(te *toolresult.ToolError, n HeldAnswer) *toolresult.ToolError {
	if n.reason == ReasonRequestTooLarge {
		// No link can carry it: the same message and steps as the hold's.
		te.PersonMessage, te.NextSteps = n.PersonMessage, n.steps
		return te
	}
	b := guidance.NewSteps()
	var lead string
	switch te.Reason {
	case guidance.ReasonNotSigned:
		s.openApprovalAgain(b, n, "Open the link and approve with your passkey: the write is not approved yet.")
		lead = "The held write was not approved yet, so nothing was applied."
	case guidance.ReasonBadSignature:
		s.openApprovalAgain(b, n, "Approve again on the page; the signature did not verify.")
		lead = "The approval signature did not verify, so nothing was applied."
	case guidance.ReasonPasskeyRevoked:
		b.AgentRunCommand(s.deps.Core.Commands.Init(), guidance.PasskeyInitText)
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
func (s *Service) openApprovalAgain(b *guidance.Steps, n HeldAnswer, text string) {
	if n.shortHeld || IsPageAddress(n.ApprovalURL) {
		b.OpenGivenLink("Open the short link the agent gave you earlier. " + text)
		return
	}
	b.OpenLink(n.ApprovalURL, text)
}

// approvalAgainMessage is the personMessage of an APPROVAL_INVALID that sends
// the person back to the page: a pointer to the short link they have while
// the pages are served, else the hold's link (a hash link names the request
// file the agent already sent).
func (s *Service) approvalAgainMessage(lead string, n HeldAnswer) (string, []toolresult.Link) {
	if n.shortHeld {
		return pointBackMessage(lead)
	}
	return ApprovalMessage(lead, HandOver{URL: n.pick.URL, Kind: n.pick.Kind, File: n.pick.File, sent: true})
}

// setupSteps: a pending setup is run by the person on their own computer;
// an expired one is renewed on the engine's machine (an OPERATOR step).
func (s *Service) setupSteps(b *guidance.Steps, te *toolresult.ToolError, f failure) string {
	if te.Reason == guidance.ReasonSetupExpired {
		return guidance.SetupExpiredSteps(b, s.deps.Core.Commands)
	}
	var se *guidance.SetupError
	if !errors.As(f.err, &se) {
		b.Fail(errors.New("a pending setup needs its code"))
		return ""
	}
	if se.ConnectOnly {
		b.CallTool(guidance.ToolStatus, map[string]any{}, "Call status: its setup problem says what the person or you do next.")
		return ""
	}
	person, ls := guidance.SetupPendingSteps(b, s.deps.Core.Commands, se.Code, se.Fingerprint, true, s.deps.Status.ConnectBudget)
	te.Links = ls
	return person
}

// sanitizeIdent quotes a column name for the SQL a step suggests: in double
// quotes, a double quote doubled and a NUL dropped.
func sanitizeIdent(name string) string {
	name = strings.ReplaceAll(name, "\x00", "")
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
