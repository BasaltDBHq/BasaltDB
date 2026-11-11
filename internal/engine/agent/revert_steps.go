package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
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
	reasonBadSignature        = "BAD_SIGNATURE"
	reasonPasskeyRevoked      = "PASSKEY_REVOKED"
	reasonRowsChanged         = "ROWS_CHANGED"
	reasonPlanFinished        = "PLAN_FINISHED"
	reasonNotSigned           = "NOT_SIGNED"
	reasonNotFinished         = "NOT_FINISHED"
	reasonReadsOnly           = "READS_ONLY"
	reasonAllChangedByPeople  = "ALL_CHANGED_BY_PEOPLE"
	reasonAlreadyReverted     = "ALREADY_REVERTED"
	toolRequestRevert         = "request_revert"
	toolRevertPlan            = "revert_plan"
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

func runCommand(command, text string) mcp.NextStep {
	return mcp.NextStep{Actor: mcp.ActorPerson, Action: mcp.ActionRunCommand, Text: text, Command: command}
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
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), "reissueLink": true},
			"Only if the link is lost or the person asks for a new one: call this for a fresh link; the old one stops working."),
	}
}

func applyingSteps(id uuid.UUID) []mcp.NextStep {
	return []mcp.NextStep{callTool(toolRevertPlan, map[string]any{argRevertID: id.String(), "pending": true, "limit": revert.MaxBatch},
		"Get the pending lines and apply them with apply_revert_batch, until pending is 0.")}
}

func appliedSteps() []mcp.NextStep {
	return []mcp.NextStep{agentStep(mcp.ActionStop, "The revert is done; do not request it again.")}
}

func expiredSteps(r ledger.Revert) []mcp.NextStep {
	return []mcp.NextStep{
		agentStep(mcp.ActionAskPerson, "Tell the person the revert was not signed in time and ask whether to request it again."),
		reviseRequestRevert(scopeArgs(r.Scope, r.ScopeID),
			"On yes, call request_revert for the same scope with the person's reason as intent."),
	}
}

// scopeArgs names a revert's scope as request_revert's arguments.
func scopeArgs(scope string, id uuid.UUID) map[string]any {
	return map[string]any{strings.ToLower(scope) + "Id": id.String()}
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
	return &mcp.ToolError{Code: CodeNotFound, Reason: reasonRevert, Message: fmt.Sprintf(
		"no revert %s requested by this agent: request one with request_revert and a changeId or runId of yours", id),
		NextSteps: []mcp.NextStep{agentStep(mcp.ActionAskPerson,
			"Ask the person for the revert id that basalt revert printed; this agent prepared no revert with that id.")}}
}

func (s *Service) badSignature(ctx context.Context, r ledger.Revert, message string) error {
	link, err := s.longRevertLink(ctx, r)
	if err != nil {
		return err
	}
	return &mcp.ToolError{Code: CodeRevertInvalid, Reason: reasonBadSignature, Message: message,
		PersonMessage: fmt.Sprintf("The code for the revert of %s %s did not verify, so nothing was reverted. Sign again on "+
			"the revert page and give the agent the new code.", strings.ToLower(r.Scope), r.ScopeID),
		NextSteps: []mcp.NextStep{
			openLink(link, "Sign again on the page; the code did not verify."),
			agentStep(mcp.ActionEndTurn, stepEndTurnPersonActsNext),
		}}
}

func (s *Service) passkeyRevoked(ctx context.Context, r ledger.Revert) error {
	link, err := s.longRevertLink(ctx, r)
	if err != nil {
		return err
	}
	return &mcp.ToolError{Code: CodeRevertInvalid, Reason: reasonPasskeyRevoked,
		Message: "the code was signed by a passkey this database does not know or that was revoked; nothing was reverted",
		PersonMessage: fmt.Sprintf("The revert of %s %s was signed with a passkey this database does not accept (unknown or "+
			"revoked), so nothing was reverted. Check your passkeys, register one if needed, then sign again.",
			strings.ToLower(r.Scope), r.ScopeID),
		NextSteps: []mcp.NextStep{
			runCommand(s.Commands.PasskeyList(), "See which passkeys this database accepts."),
			runCommand(s.Commands.Init("--add-passkey"), "Register your passkey if it is not listed."),
			openLink(link, "Then sign the revert again with that passkey."),
			agentStep(mcp.ActionEndTurn, stepEndTurnPersonActsNext),
		}}
}

func (s *Service) rowsChanged(r ledger.Revert, detail string) error {
	return &mcp.ToolError{Code: CodeRevertInvalid, Reason: reasonRowsChanged,
		Message: "the database refused the revert, nothing was reverted: " + detail,
		PersonMessage: fmt.Sprintf("Rows changed after the preview of the revert of %s %s, so nothing was reverted. The agent "+
			"requests it again for you to sign the current rows.", strings.ToLower(r.Scope), r.ScopeID),
		NextSteps: []mcp.NextStep{reviseRequestRevert(scopeArgs(r.Scope, r.ScopeID),
			"Rows changed after the preview, so nothing was reverted; request it again so the person signs the current rows.")}}
}

func alreadySigned(r ledger.Revert) error {
	return &mcp.ToolError{Code: CodeRevertInvalid, Reason: reasonPlanFinished, Message: fmt.Sprintf(
		"revert %s was already signed (status %s); nothing more was applied", r.ID, r.Status),
		NextSteps: []mcp.NextStep{
			callTool(toolRequestRevert, map[string]any{argRevertID: r.ID.String(), argWaitForSignature: 0}, "See the revert's state."),
			agentStep(mcp.ActionStop, "Do not deliver the code again."),
		}}
}

func (s *Service) revertExpired(r ledger.Revert) error {
	reason, window := reasonNotSigned, "was not signed within an hour"
	if r.SignedAt != nil {
		reason, window = reasonNotFinished, fmt.Sprintf("was not finished within %d hours of the signature", int(revert.ApplyWindow.Hours()))
	}
	scope := guard.RevertScope{Kind: revert.Scope(r.Scope), ID: r.ScopeID}
	return &mcp.ToolError{Code: CodeRevertExpired, Reason: reason,
		Message:       fmt.Sprintf("revert %s expired at %s; nothing more was reverted", r.ID, timeText(r.ExpiresAt)),
		PersonMessage: fmt.Sprintf("The revert of %s %s %s, so it expired.", strings.ToLower(r.Scope), r.ScopeID, window),
		NextSteps: []mcp.NextStep{
			agentStep(mcp.ActionAskPerson, "Ask the person whether to prepare it again."),
			runCommand(s.Commands.Revert(scope), "Prepare it again and sign within an hour; rows already restored are skipped."),
		}}
}

// prepareTimeout: the revert is too large to prepare over MCP; the person
// prepares it in a terminal and gives the agent its id.
func (s *Service) prepareTimeout(scope guard.RevertScope, sqlState string) error {
	command := s.Commands.Revert(scope)
	return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonTimeLimit, SQLState: sqlState, Message: fmt.Sprintf(
		"preparing the revert of %s %s took longer than the %d seconds an MCP call may take; nothing was prepared. "+
			"The person can prepare it in a terminal on the engine's machine, where it may take up to %d minutes: %s",
		strings.ToLower(string(scope.Kind)), scope.ID, int(guard.MCPPrepareTimeout.Seconds()), int(guard.CLIPrepareTimeout.Minutes()),
		command),
		PersonMessage: fmt.Sprintf("This revert is too large to prepare through the agent. Run: %s, sign it, then give the "+
			"agent the revert id it prints so it can apply it in batches.", command),
		NextSteps: []mcp.NextStep{
			agentStep(mcp.ActionStop, "This revert is too large to prepare here."),
			runCommand(command, fmt.Sprintf("Prepare and sign it in a terminal; the CLI allows up to %d minutes.",
				int(guard.CLIPrepareTimeout.Minutes()))),
			personStep(mcp.ActionTellAgent, "Then give the agent the revert id that basalt revert prints."),
			agentStep(mcp.ActionEndTurn, stepEndTurnPersonActsNext),
		}}
}

// nothingToRevert tells the cases of BS009 apart: the scope changed no rows
// a revert could restore (READS_ONLY), every row was already reverted, or
// people changed every row since (people win).
func (s *Service) nothingToRevert(ctx context.Context, scope guard.RevertScope, err error) error {
	te := ToolError(err)
	what := fmt.Sprintf("%s %s", strings.ToLower(string(scope.Kind)), scope.ID)
	te.Reason = s.nothingToRevertReason(ctx, scope, te.Message)
	te.Message = fmt.Sprintf("nothing to revert in %s; nothing was prepared. preview_revert shows each row and why it is "+
		"skipped (%s)", what, te.Message)
	switch te.Reason {
	case reasonReadsOnly:
		te.PersonMessage = fmt.Sprintf("Nothing to revert for %s: it only read data (or inserted rows it deleted again).", what)
		te.NextSteps = []mcp.NextStep{agentStep(mcp.ActionStop, "There is nothing to revert; do not retry.")}
	case reasonAlreadyReverted:
		te.PersonMessage = fmt.Sprintf("%s was already reverted. Reverting that revert brings the agent's changes back; rows "+
			"someone changed since are left as they are, and you sign it with your passkey.", what)
		te.NextSteps = []mcp.NextStep{
			agentStep(mcp.ActionAskPerson, "Tell the person it was already reverted; ask whether to undo that revert, which brings your work back."),
			reviseRequestRevert(map[string]any{},
				"On yes, call request_revert with the revert's changeId (revertedBy in run_history) and the person's reason as intent."),
		}
	default:
		te.PersonMessage = fmt.Sprintf("Nothing to revert for %s: every row it wrote was changed since by someone else, and "+
			"Basalt never overwrites them (people win).", what)
		te.NextSteps = []mcp.NextStep{agentStep(mcp.ActionStop, "There is nothing to revert; do not retry.")}
	}
	return te
}

func (s *Service) nothingToRevertReason(ctx context.Context, scope guard.RevertScope, detail string) string {
	if strings.Contains(detail, "changed no rows") {
		return reasonReadsOnly
	}
	texts, err := s.Reverts.PreviewRevert(ctx, scope)
	if err != nil || len(texts) == 0 {
		return reasonAllChangedByPeople
	}
	for _, t := range texts {
		l, err := revert.ParseLine(t)
		if err != nil || l.Conflict == nil || *l.Conflict != revert.ConflictAlreadyReverted {
			return reasonAllChangedByPeople
		}
	}
	return reasonAlreadyReverted
}

// withArgumentSteps gives request_revert's INVALID_ARGUMENT its one step,
// fix the arguments; any other error is returned as is.
func withArgumentSteps(err error) error {
	var ae *ArgumentError
	if !errors.As(err, &ae) {
		return err
	}
	te := ToolError(err)
	te.NextSteps = []mcp.NextStep{reviseRequestRevert(nil,
		"Fix the arguments as the message says; the tool's input schema lists them.")}
	return te
}
