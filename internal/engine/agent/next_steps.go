package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/uniqueid"
)

// Reasons of the catalog (api/mcp/errors/next-steps.json) the engine sets
// itself, beyond the ones ToolError reads from the guard.
const (
	reasonHeld                = "HELD"
	reasonHeldNoPages         = "HELD_NO_PAGES"
	reasonNoPasskey           = "NO_PASSKEY"
	reasonWaitEnded           = "WAIT_ENDED"
	reasonNoRowsNow           = "NO_ROWS_NOW"
	reasonAlreadyUsed         = "ALREADY_USED"
	reasonDifferentWrite      = "DIFFERENT_WRITE"
	reasonNotThisAgent        = "NOT_THIS_AGENT"
	reasonLineInvalid         = "LINE_INVALID"
	reasonPlanNotSigned       = "PLAN_NOT_SIGNED"
	reasonDatabaseUnreachable = "DATABASE_UNREACHABLE"
	reasonCredentialRejected  = "CREDENTIAL_REJECTED" //nolint:gosec // a catalog reason, not a credential
	reasonGuardMissing        = "GUARD_MISSING"
	reasonGuardOutdated       = "GUARD_OUTDATED"
	reasonEngineUnreachable   = "ENGINE_UNREACHABLE"
	reasonPagesOff            = "PAGES_OFF"
	reasonSetupPending        = "SETUP_PENDING"
	reasonSetupExpired        = "SETUP_EXPIRED"
	reasonRun                 = "RUN"
	reasonChange              = "CHANGE"
	reasonApproval            = "APPROVAL"
	reasonLink                = "LINK"

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
func (s *Service) Failure(tool string, args map[string]any, err error) *mcp.ToolError {
	te := ToolError(err)
	if te.Code == CodeInternal || te.Code == CodeUnavailable {
		if te.ErrorID == "" {
			te.ErrorID = uniqueid.New()
		}
		s.Log.Error("tool failed", "tool", tool, "code", te.Code, "reason", te.Reason, "error_id", te.ErrorID, "err", err)
	}
	s.addGuidance(te, failure{tool: tool, args: args, err: err})
	return te
}

// addGuidance fills te's next steps and person message from the catalog's
// entry for its code, reason and tool. A missing entry or a body that
// disagrees with it is a defect: it is logged here, and the catalog test
// fails on it.
func (s *Service) addGuidance(te *mcp.ToolError, f failure) {
	entry, ok := catalog().ErrorEntry(te.Code, te.Reason, f.tool)
	if !ok {
		s.Log.Error("no catalog entry for the error", "code", te.Code, "reason", te.Reason, "tool", f.tool)
		return
	}
	if len(te.NextSteps) == 0 {
		steps, person, err := s.errorGuidance(te, f)
		if err != nil {
			s.Log.Error("cannot build next steps", "code", te.Code, "reason", te.Reason, "tool", f.tool, "err", err)
			return
		}
		te.NextSteps = steps
		if te.PersonMessage == "" {
			te.PersonMessage = person
		}
	}
	if err := CheckPersonMessage(te.PersonMessage); err != nil {
		s.Log.Error("person message breaks its limit", "code", te.Code, "reason", te.Reason, "tool", f.tool, "err", err)
	}
	if entry.PersonMessage != (te.PersonMessage != "") {
		s.Log.Error("person message disagrees with the catalog", "code", te.Code, "reason", te.Reason, "tool", f.tool)
	}
}

// errorGuidance builds the steps and the person message for te, by code.
func (s *Service) errorGuidance(te *mcp.ToolError, f failure) ([]mcp.NextStep, string, error) {
	b, person := NewSteps(), ""
	switch te.Code {
	case CodeIntentRequired:
		b.ReviseCall(f.tool, nil, "Add an intent, one sentence saying why the change is made, then call write again.")
	case CodeStaleRead:
		s.staleReadSteps(b, te, f)
	case CodeStatementRefused:
		person = refusedSteps(b, te, f)
	case CodeRowLimitExceeded:
		person = rowLimitSteps(b)
	case CodeQueryTimeout:
		queryTimeoutSteps(b, te, f)
	case CodeApprovalRequired:
		person = s.approvalRequiredSteps(b, te)
	case CodeApprovalExpired:
		approvalExpiredSteps(b)
		person = "The held write expired before it was approved, so nothing was applied. Ask the agent to send it again if you still want it."
	case CodeApprovalInvalid:
		person = approvalInvalidSteps(b, te, f)
	case CodeRevertInvalid:
		revertInvalidSteps(b, te, f)
	case CodePermissionDenied:
		person = s.permissionDeniedSteps(b, te, f)
	case CodeNotFound:
		person = notFoundSteps(b, te, f)
	case CodeSQLError:
		sqlErrorSteps(b, te, f)
	case CodeInvalidArgument:
		invalidArgumentSteps(b, te, f)
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
func (s *Service) staleReadSteps(b *Steps, te *mcp.ToolError, f failure) {
	args, err := staleReadQuery(te.Message, f.arg(argRunID))
	if err != nil {
		// A detail the engine cannot read: the catalog's query step cannot be
		// filled in, so the agent stops and asks instead of guessing a row.
		s.Log.Error("stale read detail not understood", "err", err)
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
		conds = append(conds, fmt.Sprintf("%s = $%d", pgx.Identifier{c}.Sanitize(), i+1))
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
	string(sqlguard.ReasonParseError):         "Fix the SQL syntax as the message says, then call again.",
	string(sqlguard.ReasonMultipleStatements): "Send exactly one statement per call: split it into separate calls.",
	string(sqlguard.ReasonWrongTool):          "Send SELECT with query, and INSERT, UPDATE and DELETE with write.",
	string(sqlguard.ReasonUtility):            "Only SELECT (query) and INSERT, UPDATE, DELETE (write) are allowed: use one of them.",
	string(sqlguard.ReasonSelectInto):         "SELECT INTO creates a table: rewrite it as a plain SELECT.",
	string(sqlguard.ReasonLockingRead):        "Drop FOR UPDATE and the other lock clauses: query reads without locking.",
	string(sqlguard.ReasonMerge):              "MERGE is not allowed: use separate INSERT, UPDATE and DELETE statements.",
	string(sqlguard.ReasonDataModifyingWith):  "Move the INSERT, UPDATE or DELETE out of the WITH and send it as its own write.",
	string(sqlguard.ReasonFunction):           "Remove the call to the refused function the message names and use plain SQL.",
	string(sqlguard.ReasonNotRepeatable):      "Rewrite the write with fixed values instead of ones that change between runs, then call it again.",
}

// refusedSteps: most refusals are fixed by rewriting the statement; DDL and
// the guard's own refusals are not the agent's to get around.
func refusedSteps(b *Steps, te *mcp.ToolError, f failure) string {
	switch te.Reason {
	case string(sqlguard.ReasonDDL):
		b.Stop("Do not retry and do not look for another way to change the schema.")
		b.AskPerson("Tell the person which schema change you need; they make it themselves.")
		return "The agent tried to change the database schema (DDL). Basalt never lets an agent do that. Make the change yourself if you want it."
	case ReasonNoPrimaryKey:
		b.Stop("The table has no primary key, so its writes cannot be recorded: do not retry or work around it.")
		return fmt.Sprintf("%s has no primary key, so Basalt cannot guard writes to it and refuses them. Add a primary key to the table, "+
			"or revoke the agent's write access to it.", tableFromDetail(te.Message))
	case ReasonNotAllowed:
		b.Stop("The database refused this action for the agent: do not retry or work around it.")
		return ""
	}
	tool := f.tool
	if te.Reason == string(sqlguard.ReasonWrongTool) {
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

func queryTimeoutSteps(b *Steps, te *mcp.ToolError, f failure) {
	if te.Reason == ReasonRowLimit {
		b.ReviseCall(f.tool, nil, "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.")
		return
	}
	b.ReviseCall(f.tool, nil, "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again.")
}

func approvalExpiredSteps(b *Steps) {
	b.AskPerson("Tell the person the approval expired and the write stays blocked; ask whether to send it again.")
	b.ReviseCall(toolWrite, nil, "On yes, send the write again without approvalId, so it is held anew.")
}

func (s *Service) approvalRequiredSteps(b *Steps, te *mcp.ToolError) string {
	n := te.Approval
	if n == nil {
		b.fail(fmt.Errorf("APPROVAL_REQUIRED carries no approval"))
		return ""
	}
	again := map[string]any{argApprovalID: n.ApprovalID}
	switch te.Reason {
	case reasonHeld:
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Open the link, review the rows and approve with your passkey.")
		b.RepeatCall(toolWrite, again, 0, fmt.Sprintf("In this turn, call write again with the same arguments plus approvalId: it waits up to %d seconds for the approval.", int(DefaultApprovalWait.Seconds())))
	case reasonHeldNoPages:
		b.RunCommand(n.ApproveCommand, "Run this to open the approval page, then approve with your passkey.")
		b.RepeatCall(toolWrite, again, 0, fmt.Sprintf("In this turn, call write again with the same arguments plus approvalId: it waits up to %d seconds for the approval.", int(DefaultApprovalWait.Seconds())))
	case reasonNoPasskey:
		b.RunCommand(s.Commands.Init("--add-passkey"), "Register a passkey first: approvals are signed with one.")
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Then open the link and approve the held write.")
		b.EndTurn("End your turn: the person acts next.")
	case reasonWaitEnded:
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Open the link and approve with your passkey.")
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
func approvalInvalidSteps(b *Steps, te *mcp.ToolError, f failure) string {
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

func revertInvalidSteps(b *Steps, te *mcp.ToolError, f failure) {
	id := f.arg(argRevertID)
	switch te.Reason {
	case reasonLineInvalid:
		b.CallTool(toolRevertPlan, map[string]any{argRevertID: id, "pending": true}, "Read the plan's pending lines again and send only those.")
	case reasonPlanNotSigned:
		b.CallTool(toolRevertPlan, map[string]any{argRevertID: id}, "Read the plan: it is not signed yet.")
		b.EndTurn("The person signs the plan with basalt revert; end your turn and apply it when they say they signed.")
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

// permissionDeniedSteps names the grant that would give the agent the
// access it lacked: init with the saved flags plus the table.
func (s *Service) permissionDeniedSteps(b *Steps, te *mcp.ToolError, f failure) string {
	b.Stop("The agent role may not do this: do not retry or look for another route.")
	b.AskPerson("Tell the person which access is missing and ask them to grant it.")
	flag := "write"
	if f.tool == toolQuery {
		flag = "read"
	}
	command, what := s.Commands.Init("--dry-run"), "access to what it asked for"
	if m := deniedTable.FindStringSubmatch(te.Message); m != nil {
		// Only a schema-qualified plain name can be added to the access list
		// safely; Postgres usually names the table without its schema, and
		// then the person sees the plan and adds the table themselves.
		if grant, err := s.Commands.Grant(flag, m[1]); err == nil {
			command, what = grant, flag+" access to "+m[1]
		}
	}
	b.RunCommand(command, "Show the person this command: it gives the agent the missing access, and init asks for the admin connection string itself.")
	b.TellAgent("Tell the agent once the access is granted.")
	return fmt.Sprintf("The agent was denied %s. If it should have it, run the command the agent shows you, then tell the agent.", what)
}

func notFoundSteps(b *Steps, te *mcp.ToolError, f failure) string {
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
		b.AskPerson("Ask the person for the revert id that basalt revert printed; this agent prepared no revert with that id.")
	case reasonLink:
		b.TellAgent("Ask the agent for the link again.")
		return "This link is incomplete, expired or was replaced by a newer one. Ask the agent for the link again."
	default:
		b.fail(fmt.Errorf("NOT_FOUND has no reason %q", te.Reason))
	}
	return ""
}

func sqlErrorSteps(b *Steps, te *mcp.ToolError, f failure) {
	if te.Reason == reasonNoRowsNow {
		b.ReviseCall(f.tool, nil, "The write now changes no rows: read the rows again with query and decide before writing.")
		return
	}
	b.ReviseCall(f.tool, nil, "Fix the statement as the database's message says, then call again.")
}

func invalidArgumentSteps(b *Steps, te *mcp.ToolError, f failure) {
	if te.Reason == ReasonStaleCursor {
		b.RepeatCall(f.tool, map[string]any{"cursor": nil}, 0, "The cursor is no longer valid: call again without cursor to start from the first page.")
		return
	}
	b.ReviseCall(f.tool, nil, "Fix the arguments as the message says; the tool's input schema lists them.")
}

// unavailableSteps: a database the engine cannot reach is retried once; the
// machine problems are the person's to fix, with the command for it.
func (s *Service) unavailableSteps(b *Steps, te *mcp.ToolError, f failure) string {
	person := func(command, problem string) string {
		b.RunCommand(command, "Run this to fix it.")
		b.TellAgent("Tell the agent when it is done.")
		b.Stop("Do not retry until the person says it is fixed.")
		return fmt.Sprintf("%s Run: %s then tell the agent.", problem, command)
	}
	switch te.Reason {
	case reasonDatabaseUnreachable:
		b.RepeatCall(f.tool, nil, 0, "Try the same call once more, in case the database was only briefly busy.")
		b.AskPerson("Then tell the person the database cannot be reached and ask them to check that Postgres is running.")
		return "The agent cannot reach the database. Check that Postgres is running and reachable from the machine the engine runs on."
	case reasonCredentialRejected:
		return person(s.Commands.Init("--rotate-password"), "The database refused the agent's credential (its password changed or was never right); this sets a new one and prints the restart command.")
	case reasonGuardMissing:
		return person(s.Commands.Init(""), "The guard is not installed in this database (or was removed); this installs it again with the saved flags.")
	case reasonGuardOutdated:
		return person(s.Commands.Upgrade(), "The guard in this database is older than this engine needs; this upgrades it.")
	case reasonEngineUnreachable:
		return person(s.Commands.EngineStart(), "The agent cannot reach the engine, so it is not running.")
	case reasonSetupPending, reasonSetupExpired:
		return s.setupSteps(b, te, f)
	case reasonPagesOff:
		b.CallTool(toolListPending, map[string]any{}, "Read the held writes: each has the command the person runs, since this engine serves no pages.")
		return ""
	}
	b.fail(fmt.Errorf("UNAVAILABLE has no reason %q", te.Reason))
	return ""
}

// approvalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page: not signed yet, a signature the
// database refused, or a passkey it does not accept. The link in its message
// follows the link budget like the hold's; no new short link is issued here.
func (s *Service) approvalLinkError(te *mcp.ToolError, n heldNotice) *mcp.ToolError {
	b := NewSteps()
	pick := chooseLink(n.shortURL, n.longURL, s.LinkBudget)
	var lead string
	switch te.Reason {
	case reasonNotSigned:
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Open the link and approve with your passkey: the write is not approved yet.")
		lead = "The held write was not approved yet, so nothing was applied."
	case reasonBadSignature:
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Approve again on the page; the code did not verify.")
		lead = "The approval code did not verify, so nothing was applied."
	case reasonPasskeyRevoked:
		b.RunCommand(s.Commands.PasskeyList(), "See which passkeys this database accepts.")
		b.RunCommand(s.Commands.Init("--add-passkey"), "Register your passkey with this command: it adds the one you use and changes nothing else.")
		b.OpenLink(n.ApprovalURL, n.ApproveCommand, "Then approve the held write with that passkey.")
		lead = "That passkey is not accepted here (unknown or revoked), so nothing was applied. Check your passkeys, register one if needed, then approve again."
	default:
		return te
	}
	te.PersonMessage, te.Links = approvalMessage(lead, pick, n.ApproveCommand)
	b.EndTurn("End your turn: the person acts next.")
	steps, err := b.Build()
	if err != nil {
		s.Log.Error("cannot build approval steps", "reason", te.Reason, "err", err)
		return te
	}
	te.NextSteps = steps
	return te
}

// SetupError is a call refused because the agent's setup from the laptop has
// not run (CONTRACT.md, Setup from your laptop). Code is the pending setup
// code, which the person runs on their own computer; Expired when it ran out.
type SetupError struct {
	Code    string
	Expired bool
}

func (e *SetupError) Error() string {
	if e.Expired {
		return "the agent's setup code expired before it was used"
	}
	return "the agent's setup has not run yet"
}

var setupCode = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// setupSteps: a pending setup is run by the person on their own computer;
// an expired one is renewed on the engine's machine (an OPERATOR step, which
// the person runs: the engine has no operatedBy AGENT mode yet).
func (s *Service) setupSteps(b *Steps, te *mcp.ToolError, f failure) string {
	if te.Reason == reasonSetupExpired {
		command := s.Commands.Init("--remote --new-code")
		b.RunCommand(command, "Make a new setup code: this asks for the admin connection string itself.")
		b.EndTurn("End your turn: the person acts next.")
		return "The setup code for this agent expired before it was used. Run this to make a new one, then follow the steps it prints: " + command
	}
	var se *SetupError
	if !errors.As(f.err, &se) || !setupCode.MatchString(se.Code) {
		b.fail(errors.New("a pending setup needs its code"))
		return ""
	}
	command := s.Commands.Init("--setup-code " + se.Code)
	b.RunCommand(command, "On your own computer, run this to finish the agent's setup.")
	b.TellAgent("Tell the agent when it is done.")
	b.EndTurn("End your turn: the person acts next.")
	b.CallTool("status", map[string]any{}, "When the person says it is done, check that the agent is ready.")
	return "This agent's setup has not run yet. On your own computer, run: " + command + " then tell the agent."
}
