package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// request_revert's next steps, per api/mcp/errors/next-steps.json and the
// actionable-errors design (section 4.3): results REQUESTED, WAIT_ENDED,
// APPLYING, APPLIED and EXPIRED, and the error cases the tool returns.

// Reasons of the error cases request_revert returns (CONTRACT.md, Next
// steps per code).
const (
	reasonRevert              = "REVERT"
	reasonBadSignature        = action.ReasonBadSignature
	reasonPasskeyRevoked      = action.ReasonPasskeyRevoked
	reasonRowsChanged         = action.ReasonRowsChanged
	reasonPlanFinished        = action.ReasonPlanFinished
	reasonNotSigned           = action.ReasonNotSigned
	reasonNotFinished         = "NOT_FINISHED"
	reasonReadsOnly           = "READS_ONLY"
	reasonAllChangedByPeople  = "ALL_CHANGED_BY_PEOPLE"
	reasonAlreadyReverted     = "ALREADY_REVERTED"
	toolRequestRevert         = "request_revert"
	toolRevertPlan            = "revert_plan"
	toolApplyRevertBatch      = "apply_revert_batch"
	toolListRuns              = "list_runs"
	argRevertID               = "revertId"
	argWaitForSignature       = "waitForSignature"
	stepEndTurnPersonActsNext = "End your turn: the person acts next."
)

func agentStep(action, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorAgent, Action: action, Text: text}
}

func personStep(action, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorPerson, Action: action, Text: text}
}

func callTool(tool string, args map[string]any, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionCallTool, Text: text, Tool: tool, Arguments: args}
}

// reviseRequestRevert: call request_revert again, with what the agent adds.
func reviseRequestRevert(args map[string]any, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionReviseCall, Text: text, Tool: toolRequestRevert, Arguments: args}
}

func openLink(url, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorPerson, Action: mcp.ActionOpenLink, Text: text, URL: url}
}

// requestedSteps: the person signs at link, the agent waits once.
func requestedSteps(id uuid.UUID, link string) []mcp.NextStep {
	return []mcp.NextStep{
		openLink(link, "Open the link, review the rows and sign with your passkey."),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argWaitForSignature: int(DefaultRevertWait.Seconds())},
			fmt.Sprintf("In this turn, call request_revert once with revertId: it waits up to %d seconds.", int(DefaultRevertWait.Seconds()))),
	}
}

// The person's OPEN_LINK text after a wait: the short link given earlier
// (the step carries no url), or, when the engine serves no pages, the long
// link the step carries.
const (
	waitEndedShortLink = "Open the short link the agent gave you earlier and sign with your passkey."
	waitEndedLongLink  = "Open the link and sign with your passkey; then give the agent the code the page shows."
)

// waitEndedSteps: not signed yet. The person signs at the link already
// given (link is "" with local pages: the agent shows the short link it
// still has; else the long link); the agent does not wait again, and gets
// a fresh short link only when the person lost theirs.
func waitEndedSteps(id uuid.UUID, link, open string) []mcp.NextStep {
	return []mcp.NextStep{
		openLink(link, open),
		personStep(mcp.ActionTellAgent, "Tell the agent when you have signed, or that you lost the link."),
		agentStep(mcp.ActionEndTurn, "Do not wait again: end your turn, showing personMessage and the revert link you gave earlier."),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argWaitForSignature: 0},
			"When the person says they signed, call it once more; it returns at once."),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argReissueLink: true},
			"For a lost link, or when the person asks for a new one, call this: it gives a fresh link and the old one stops working."),
	}
}

// widenedMessage opens every wait-form personMessage for a revert the
// person widened (CONTRACT.md, request_revert, Wait form).
const widenedMessage = "You changed the scope on the signing page; the agent cannot see what you added."

// widenedWaitSteps: a widened revert not signed yet. The steps of
// waitEndedSteps, but the person signs on the page they widened on (the
// agent holds no link to it), and a reissue resets the revert to the
// agent's proposal (owner, Q8).
func widenedWaitSteps(id uuid.UUID) []mcp.NextStep {
	return []mcp.NextStep{
		openLink("", "Sign with your passkey on the page where you changed the scope."),
		personStep(mcp.ActionTellAgent, "Tell the agent when you have signed."),
		agentStep(mcp.ActionEndTurn, "Do not wait again: end your turn, showing personMessage; you have no link to the person's scope."),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argWaitForSignature: 0},
			"When the person says they signed, call it once more; it returns at once."),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argReissueLink: true},
			"Only if the person asks for a new link: it resets the revert to your own work, dropping what they added."),
	}
}

func applyingSteps(id uuid.UUID) []mcp.NextStep {
	return []mcp.NextStep{callTool(toolRevertPlan, map[string]any{argRevertID: id.String(), "pending": true, "limit": revert.MaxBatch},
		"Get the pending lines and apply them with apply_revert_batch, until pending is 0.")}
}

func appliedSteps() []mcp.NextStep {
	return []mcp.NextStep{agentStep(mcp.ActionStop, "The revert is done; do not request it again.")}
}

// rejectedSteps: the person rejected the revert on the signing page.
func rejectedSteps() []mcp.NextStep {
	return []mcp.NextStep{agentStep(mcp.ActionStop,
		"The person rejected the revert and nothing was reverted. Do not request it again on your own.")}
}

// rejectedMessage is the line for the person about a rejected revert, with
// the note they wrote, if any.
func rejectedMessage(r ledger.Revert) string {
	msg := "The revert was rejected on the signing page. Nothing was reverted."
	if r.RejectNote != "" {
		msg += " Your note: " + r.RejectNote
	}
	return msg
}

func expiredSteps(r ledger.Revert) []mcp.NextStep {
	return []mcp.NextStep{
		agentStep(mcp.ActionAskPerson, "Tell the person the revert was not signed in time and ask whether to request it again."),
		reviseRequestRevert(scopeArgs(proposalOf(r)),
			"On yes, call request_revert for the same scope with the person's reason as intent."),
	}
}

// scopeArgs names a revert scope as request_revert's arguments, its runs
// and tables filters included, so a request the agent makes from these
// steps covers no more than the person was shown.
func scopeArgs(scope action.Scope) map[string]any {
	args := map[string]any{strings.ToLower(string(scope.Kind)) + "Id": scope.ID.String()}
	if len(scope.Runs) > 0 {
		runs := make([]string, 0, len(scope.Runs))
		for _, id := range scope.Runs {
			runs = append(runs, id.String())
		}
		args["runs"] = runs
	}
	if len(scope.Tables) > 0 {
		args["tables"] = scope.Tables
	}
	return args
}

// proposalOf is the scope of revert r with the runs and tables of the
// select its binding carries (the agent's proposal, or the person's
// narrowing of it), so requesting r again keeps them.
func proposalOf(r ledger.Revert) action.Scope {
	scope := action.Scope{Kind: revert.Scope(r.Scope), ID: r.ScopeID}
	// The agent's view hides a widened revert's binding (version 20): a new
	// request then names only the revert's scope, a change, run or task of
	// the agent's own (the person widens a run at most to its task), which
	// the guard limits to the agent's own work.
	if r.BindingText == "" {
		return scope
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		// The guard built the binding; one that does not parse fails the
		// revert's link and message first (revertNotice). The steps keep the
		// scope alone, and the page shows the person what a new request holds.
		return scope
	}
	scope.Runs, scope.Tables = b.Select.Runs, b.Select.Tables
	return scope
}

// maxFilterTableChars is how much of a filter's first table name a
// person's message shows; the page shows them all.
const maxFilterTableChars = 32

// filterText names scope's runs and tables filters for a person, "" when it
// has none: the count of runs, the first table and how many more.
func filterText(scope action.Scope) string {
	var parts []string
	if n := len(scope.Runs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d of its runs", n))
	}
	switch n := len(scope.Tables); {
	case n == 1:
		parts = append(parts, "table "+shown(scope.Tables[0], maxFilterTableChars))
	case n > 1:
		parts = append(parts, fmt.Sprintf("tables %s and %d more", shown(scope.Tables[0], maxFilterTableChars), n-1))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", only " + strings.Join(parts, " and ")
}

// longRevertLink is r's long link: it carries the whole request, so the
// engine can give it again when the short link is gone.
func (s *Service) longRevertLink(ctx context.Context, r ledger.Revert) (string, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return "", err
	}
	return revert.Request{RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, CredentialIDs: ids}.URL(s.PagesBase)
}

func revertNotFound(id uuid.UUID) error {
	return &mcp.ToolError{
		Code: CodeNotFound, Reason: reasonRevert, Message: fmt.Sprintf(
			"no revert %s requested by this agent: request one with request_revert and a changeId or runId of yours", id),
		NextSteps: []mcp.NextStep{agentStep(mcp.ActionAskPerson,
			"Ask the person which revert they mean; this agent prepared no revert with that id.")},
	}
}

// signingLink is the OPEN_LINK step of a refusal that sends the person back
// to sign r again, with text after what the step says first. It follows the
// link budget (CONTRACT.md, The request file and pasted blocks): while the
// engine serves the pages the person has the short link, so the step carries
// no url and never the long link; without them it carries the link the
// request handed over (the long link within the budget, else the hash link,
// whose request file the agent already sent; no requestFile again). A
// widened revert has no link: its only one is the page the person widened
// on (the agent cannot read its binding, RS-5).
func (s *Service) signingLink(ctx context.Context, r ledger.Revert, text string) (mcp.NextStep, error) {
	switch {
	case r.Widened:
		return openLink("", text), nil
	case s.PagesOrigin != "":
		return openLink("", "Open the short link the agent gave you earlier. "+text), nil
	}
	pick, err := s.restatedRevertLink(ctx, r)
	if err != nil {
		return mcp.NextStep{}, err
	}
	if pick.Kind == linkPage || pick.Kind == linkNone {
		return openLink("", "Open the short link the agent gave you earlier. "+text), nil
	}
	if pick.Kind == linkHash {
		text = "Open the link with the request file the agent sent you earlier. " + text
	}
	return openLink(pick.URL, text), nil
}

// restatedRevertLink is r's link in a result that names it without issuing
// a new one: the long link while the engine serves the pages (the person has
// the short link), else the link the budget chooses, which over the budget
// is the hash link with its request (CONTRACT.md, The request file and
// pasted blocks).
//
// A request too large for a long link is restated as the page's address:
// linkPage when a short link given earlier carries it, else linkNone
// (CONTRACT.md, Large values, rule 3).
func (s *Service) restatedRevertLink(ctx context.Context, r ledger.Revert) (handOver, error) {
	req := revertRequestOf(r)
	long, tooLarge, err := longOrTooLarge(req, func() (string, error) { return s.longRevertLink(ctx, r) })
	if err != nil {
		return handOver{}, err
	}
	if tooLarge {
		kind := linkNone
		if s.carriesLarge(req.Cost) {
			kind = linkPage
		}
		return handOver{URL: s.pageAddress(links.Revert, r.ID), Kind: kind}, nil
	}
	if s.PagesOrigin != "" {
		return handOver{URL: long, Kind: linkLong}, nil
	}
	return chooseLink("", long, s.LinkBudget, links.RevertFile(r.ID))
}

// revertTitle names revert r for the person, starting lowercase: its scope,
// or for a widened revert no scope, since the agent relays the message and
// the scope the person chose is theirs (RS-5).
func revertTitle(r ledger.Revert) string {
	if r.Widened {
		return "the revert you widened on the signing page"
	}
	return "the revert of " + scopeText(r.Scope, r.ScopeID)
}

// sentence starts s with a capital letter.
func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *Service) badSignature(ctx context.Context, r ledger.Revert, message string) error {
	open, err := s.signingLink(ctx, r, signAgainText)
	if err != nil {
		return err
	}
	return s.badSignatureWith(open, r, message)
}

// The OPEN_LINK texts of the refusals that send the person back to sign.
const (
	signAgainText   = "Sign again on the page; the code did not verify."
	signRevokedText = "Then sign the revert again with that passkey."
)

// badSignatureWith is REVERT_INVALID BAD_SIGNATURE with open, the step to
// the revert page (signingLink).
func (s *Service) badSignatureWith(open mcp.NextStep, r ledger.Revert, message string) error {
	return &mcp.ToolError{
		Code: CodeRevertInvalid, Reason: reasonBadSignature, Message: message,
		PersonMessage: fmt.Sprintf("The code for %s did not verify, so nothing was reverted. Sign again on "+
			"the revert page and give the agent the new code.", revertTitle(r)),
		NextSteps: []mcp.NextStep{
			open,
			agentStep(mcp.ActionEndTurn, stepEndTurnPersonActsNext),
		},
	}
}

func (s *Service) passkeyRevoked(ctx context.Context, r ledger.Revert) error {
	open, err := s.signingLink(ctx, r, signRevokedText)
	if err != nil {
		return err
	}
	return s.passkeyRevokedWith(open, r)
}

// requestAgainText is the text of the step that prepares an expired revert
// again.
const requestAgainText = "On yes, call request_revert with these arguments and the person's reason as intent; rows already restored are skipped."

// passkeyRevokedWith is REVERT_INVALID PASSKEY_REVOKED with open, the step
// to the revert page (signingLink).
func (s *Service) passkeyRevokedWith(open mcp.NextStep, r ledger.Revert) error {
	return &mcp.ToolError{
		Code: CodeRevertInvalid, Reason: reasonPasskeyRevoked,
		Message: "the code was signed by a passkey this database does not know or that was revoked; nothing was reverted",
		PersonMessage: fmt.Sprintf("%s was signed with a passkey this database does not accept (unknown or "+
			"revoked), so nothing was reverted. The agent gives you a link to register the passkey you use; then sign again.",
			sentence(revertTitle(r))),
		NextSteps: []mcp.NextStep{
			{Actor: mcp.ActorAgent, Action: mcp.ActionRunCommand, Text: passkeyInitText, Command: s.Commands.Init()},
			open,
			agentStep(mcp.ActionEndTurn, stepEndTurnPersonActsNext),
		},
	}
}

func (s *Service) rowsChanged(r ledger.Revert, detail string) error {
	return &mcp.ToolError{
		Code: CodeRevertInvalid, Reason: reasonRowsChanged,
		Message: "the database refused the revert, nothing was reverted: " + detail,
		PersonMessage: fmt.Sprintf("Rows changed after the preview of %s%s, so nothing was reverted. The agent "+
			"requests it again for you to sign the current rows.", revertTitle(r), filterText(proposalOf(r))),
		NextSteps: []mcp.NextStep{reviseRequestRevert(scopeArgs(proposalOf(r)),
			"Rows changed after the preview, so nothing was reverted; request it again so the person signs the current rows.")},
	}
}

// nothingSigned is apply_revert's NOTHING_TO_REVERT: the signed scope has
// no row to restore. Its detail names the scope, so the answer is built
// here, without it for a widened revert (RS-5).
func nothingSigned(r ledger.Revert) error {
	te := &mcp.ToolError{
		Code: CodeNothingToRevert, Reason: reasonReadsOnly,
		Message:       fmt.Sprintf("revert %s has no row to restore in the scope that was signed; nothing was reverted", r.ID),
		PersonMessage: sentence(revertTitle(r)) + " has no row to restore in the scope you signed, so nothing was reverted.",
		NextSteps:     []mcp.NextStep{agentStep(mcp.ActionStop, "There is nothing to revert; do not retry.")},
	}
	if r.Skipped > 0 {
		te.Reason = reasonAllChangedByPeople
		te.PersonMessage = sentence(revertTitle(r)) + " has no row to restore: every row in it was changed since by someone " +
			"else, and Basalt never overwrites them (people win). Nothing was reverted."
	}
	return te
}

func alreadySigned(r ledger.Revert) error {
	msg := fmt.Sprintf("revert %s was already signed (status %s); nothing more was applied", r.ID, r.Status)
	if r.Status == ledger.RevertRejected {
		msg = fmt.Sprintf("revert %s was rejected by the person on the revert page; nothing was reverted", r.ID)
	}
	return &mcp.ToolError{
		Code: CodeRevertInvalid, Reason: reasonPlanFinished, Message: msg,
		NextSteps: []mcp.NextStep{
			callTool(toolRequestRevert, map[string]any{argRevertID: r.ID.String(), argWaitForSignature: 0}, "See the revert's state."),
			agentStep(mcp.ActionStop, "Do not deliver the code again."),
		},
	}
}

func (s *Service) revertExpired(r ledger.Revert) error {
	reason, window := reasonNotSigned, "was not signed within an hour"
	if r.SignedAt != nil {
		reason, window = reasonNotFinished, fmt.Sprintf("was not finished within %d hours of the signature", int(revert.ApplyWindow.Hours()))
	}
	return &mcp.ToolError{
		Code: CodeRevertExpired, Reason: reason,
		Message:       fmt.Sprintf("revert %s expired at %s; nothing more was reverted", r.ID, timeText(r.ExpiresAt)),
		PersonMessage: fmt.Sprintf("%s %s, so it expired. To revert it still, ask the agent to prepare it again.", sentence(revertTitle(r)), window),
		NextSteps: []mcp.NextStep{
			agentStep(mcp.ActionAskPerson, "Ask the person whether to prepare it again."),
			reviseRequestRevert(scopeArgs(proposalOf(r)), requestAgainText),
		},
	}
}

// prepareTimeout: the revert is too large to prepare in one MCP call. The
// agent stops and asks the person whether a narrower revert (some runs or
// tables) will do; there is no other way to prepare it.
func (s *Service) prepareTimeout(tool string, scope action.Scope, sqlState string) error {
	te := &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonTimeLimit, SQLState: sqlState, Message: fmt.Sprintf(
		"preparing the revert of %s %s took longer than the %d seconds an MCP call may take; nothing was prepared. "+
			"A narrower revert, with runs or tables, may fit.",
		strings.ToLower(string(scope.Kind)), scope.ID, int(guard.MCPPrepareTimeout.Seconds()))}
	what := "prepare"
	if tool == toolPreviewRevert {
		what = "preview"
	}
	te.PersonMessage = fmt.Sprintf("This revert is too large for the agent to %s in one call, so nothing was prepared. "+
		"The agent can revert a part of it instead: only some runs or tables.", what)
	steps, err := NewSteps().Stop("This revert is too large to prepare here: do not retry it as it is.").
		AskPerson("Ask the person whether a narrower revert will do: request_revert with runs or tables.").
		EndTurn(stepEndTurnPersonActsNext).Build()
	if err != nil {
		return err
	}
	te.NextSteps = steps
	return te
}

// nothingToRevert tells the cases of BS009 apart: the scope changed no rows
// a revert could restore (READS_ONLY), every row was already reverted, or
// people changed every row since (people win).
func (s *Service) nothingToRevert(ctx context.Context, tool string, scope action.Scope, err error) error {
	detail := ToolError(err).Message
	if strings.Contains(detail, "changed no rows") {
		return s.nothingToRevertError(ctx, tool, scope, reasonReadsOnly, detail)
	}
	pv, perr := s.Store.PreviewRevert(ctx, scope, "", 1)
	if perr != nil {
		pv = action.PreviewPage{}
	}
	return s.nothingToRevertError(ctx, tool, scope, skipReason(pv), detail)
}

// nothingToRevertError builds NOTHING_TO_REVERT for reason.
func (s *Service) nothingToRevertError(ctx context.Context, tool string, scope action.Scope, reason, detail string) error {
	what := fmt.Sprintf("%s %s", strings.ToLower(string(scope.Kind)), scope.ID)
	te := &mcp.ToolError{Code: CodeNothingToRevert, Reason: reason}
	te.Message = fmt.Sprintf("nothing to revert in %s; nothing was prepared (%s)", what, detail)
	if tool == toolRequestRevert {
		te.Message = fmt.Sprintf("nothing to revert in %s; nothing was prepared. preview_revert shows each row and why it is "+
			"skipped (%s)", what, detail)
	}
	b := NewSteps()
	switch reason {
	case reasonReadsOnly:
		te.PersonMessage = fmt.Sprintf("Nothing to revert for %s: it only read data (or inserted rows it deleted again).", what)
		b.Stop("There is nothing to revert; do not retry.")
	case reasonAlreadyReverted:
		by, err := s.Store.RevertedBy(ctx, scope)
		if err != nil {
			s.Log.Error("find the revert of a reverted scope", "scope", what, "err", err)
		}
		args, named := map[string]any{}, ""
		if by != uuid.Nil {
			args[argChangeID] = by.String()
			named = fmt.Sprintf(" (the revert's change %s)", by)
		}
		te.PersonMessage = fmt.Sprintf("%s was already reverted%s. Reverting that revert brings the agent's changes back; rows "+
			"someone changed since are left as they are, and you sign it with your passkey.", what, named)
		b.AskPerson("Tell the person it was already reverted; ask whether to undo that revert, which brings your work back.")
		b.ReviseCall(toolRequestRevert, args, "On yes, call request_revert with the revert's changeId and the person's reason as intent.")
	default:
		te.PersonMessage = fmt.Sprintf("Nothing to revert for %s: every row it wrote was changed since by someone else, and "+
			"Basalt never overwrites them (people win).", what)
		b.Stop("There is nothing to revert; do not retry.")
	}
	if scope.Kind == revert.ScopeTask {
		// The agent's own lines are empty, but other agents' may not be
		// (RS-6): the person widens to them on the signing page of a revert
		// another agent in the task requests.
		te.PersonMessage += " To revert other agents' changes in this task, ask an agent that changed rows in it to request " +
			"the revert: you can include the others' changes on its signing page."
	}
	steps, err := b.Build()
	if err != nil {
		return err
	}
	te.NextSteps = steps
	return te
}

// skipReason is why a preview with no line to restore has nothing to revert:
// every line skipped because it was reverted already, or because people
// changed the rows since.
func skipReason(pv action.PreviewPage) string {
	if pv.Lines > 0 && pv.AllAlreadyReverted {
		return reasonAlreadyReverted
	}
	return reasonAllChangedByPeople
}
