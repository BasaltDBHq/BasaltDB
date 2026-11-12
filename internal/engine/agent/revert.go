package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// RevertStore previews reverts on the agent's credential, reads the large
// plans it prepared and applies batches of them. Signing a revert is not an
// agent's to do: it needs the person's passkey (basalt revert).
// ApplyRevert only relays an assertion the person's page made, for the
// local pages (CONTRACT.md, Local pages); no MCP tool reaches it, and
// Postgres verifies the signature.
type RevertStore interface {
	PreviewRevert(ctx context.Context, scope guard.RevertScope) ([]string, error)
	// RevertedBy is the change record of the latest revert that covered scope
	// (a revert's own change, which request_revert accepts to redo the work),
	// or uuid.Nil when none did.
	RevertedBy(ctx context.Context, scope guard.RevertScope) (uuid.UUID, error)
	PrepareRevert(ctx context.Context, scope guard.RevertScope, intent string, timeout time.Duration) (guard.PreparedRevert, error)
	HasChange(ctx context.Context, id uuid.UUID) (bool, error)
	// HasTaskRun reports whether the agent has a run with this task id.
	HasTaskRun(ctx context.Context, id uuid.UUID) (bool, error)
	FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error)
	RevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error)
	ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (guard.BatchResult, error)
	ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error)
	// RescopeRevert and ResetRevert change a pending revert's scope for the
	// person, and put it back to the proposal for the agent's reissue, each
	// canceled past timeout.
	RescopeRevert(ctx context.Context, req guard.RescopeRequest, timeout time.Duration) (guard.RescopedRevert, error)
	ResetRevert(ctx context.Context, id uuid.UUID, timeout time.Duration) (guard.RescopedRevert, error)
	// RevertNonce is the rescope nonce of a revert the role prepared.
	RevertNonce(ctx context.Context, id uuid.UUID) ([]byte, error)
}

// PreviewRevertParams are preview_revert's validated arguments: the scope
// (exactly one id) and a page of lines.
type PreviewRevertParams struct {
	pagination.Params
	Scope guard.RevertScope
}

// RevertPreview is one page of what a revert would do, with the totals of
// the whole preview and the command the person runs to revert.
type RevertPreview struct {
	Scope   guard.RevertScope
	Rows    int
	Skipped int
	Command string
	Page    pagination.Page[revert.Line]
	// PersonMessage and NextSteps say what happens next (CONTRACT.md, Next steps).
	PersonMessage string
	NextSteps     []mcp.NextStep
}

// PreviewRevert returns what reverting the scope would restore and skip.
// It changes nothing: the guard runs the revert on trial and undoes it.
// The scope must be the agent's own (RS-1): another agent's id answers
// NOT_FOUND before any guard call.
func (s *Service) PreviewRevert(ctx context.Context, p PreviewRevertParams) (RevertPreview, error) {
	if err := s.checkOwnScope(ctx, p.Scope); err != nil {
		return RevertPreview{}, err
	}
	texts, err := s.Reverts.PreviewRevert(ctx, p.Scope)
	if err != nil {
		return RevertPreview{}, s.prepareError(ctx, toolPreviewRevert, p.Scope, err)
	}
	start, err := lineAfter(texts, p.Cursor)
	if err != nil {
		return RevertPreview{}, err
	}
	if allSkipped(texts) {
		// Every line is skipped: nothing a revert could restore (AE-8, AE-14).
		return RevertPreview{}, s.nothingToRevertError(ctx, toolPreviewRevert, p.Scope, skipReason(texts), "every row is skipped")
	}
	out := RevertPreview{Scope: p.Scope, Command: s.Commands.Revert(p.Scope)}
	lines := make([]revert.Line, 0, len(texts))
	for _, text := range texts {
		l, err := revert.ParseLine(text)
		if err != nil {
			return RevertPreview{}, fmt.Errorf("guard returned a bad revert line: %w", err)
		}
		lines = append(lines, l)
		if l.Action == revert.ActionRestore {
			out.Rows++
		}
	}
	out.Skipped = len(lines) - out.Rows
	end := min(start+p.Limit, len(lines))
	out.Page.Items = lines[start:end]
	if end < len(lines) {
		out.Page.NextCursor = pagination.EncodeNameCursor(lineHash(texts[end-1]))
	}
	if out.PersonMessage, out.NextSteps, err = s.previewGuidance(out); err != nil {
		return RevertPreview{}, err
	}
	return out, nil
}

// lineAfter is the index of the first line after the cursor's line. The
// cursor names a line by its hash (keyset on the signed line order), so a
// preview that changed between pages is refused rather than skipped over.
func lineAfter(texts []string, cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	hash, err := pagination.DecodeNameCursor(cursor)
	if err != nil {
		return 0, &ArgumentError{Message: "invalid cursor", Reason: ReasonStaleCursor}
	}
	for i, t := range texts {
		if lineHash(t) == hash {
			return i + 1, nil
		}
	}
	return 0, &ArgumentError{Message: "the cursor's line is no longer in the preview: the rows changed, start from the first page", Reason: ReasonStaleCursor}
}

func lineHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// RevertPlanParams are revert_plan's validated arguments: a batched plan
// and one page of its lines (only pending ones with Outcome PENDING).
type RevertPlanParams = ledger.RevertLineParams

// RevertPlanLine is one line of a batched plan with its signed line parsed.
type RevertPlanLine struct {
	ledger.RevertLine
	Plan revert.Line
}

// RevertPlan is a batched plan's state and one page of its lines; while
// the person has not signed it, the link to sign it and one line for them.
type RevertPlan struct {
	Revert        ledger.Revert
	Page          pagination.Page[RevertPlanLine]
	RevertURL     string
	PersonMessage string
	NextSteps     []mcp.NextStep
	Links         []mcp.Link
}

// RevertPlan returns a large revert plan this agent prepared, its progress
// and one page of its lines, for the agent to apply with ApplyRevertBatch
// once the person signed it.
func (s *Service) RevertPlan(ctx context.Context, p RevertPlanParams) (RevertPlan, error) {
	r, err := s.Reverts.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return RevertPlan{}, &mcp.ToolError{Code: CodeNotFound, Reason: reasonRevert, Message: fmt.Sprintf("no revert %s prepared by this agent", p.RevertID)}
	}
	if err != nil {
		return RevertPlan{}, err
	}
	if !r.Batched {
		return RevertPlan{}, &ArgumentError{Message: fmt.Sprintf(
			"revert %s has %d lines: basalt revert applies it in one call, there is no plan to apply in batches", r.ID, r.Rows+r.Skipped)}
	}
	page, err := s.Reverts.RevertLines(ctx, p)
	if err != nil {
		return RevertPlan{}, err
	}
	out := RevertPlan{Revert: r, Page: pagination.Page[RevertPlanLine]{NextCursor: page.NextCursor}}
	if r.Status == ledger.RevertPending {
		n, err := s.revertNotice(ctx, r)
		if err != nil {
			return RevertPlan{}, err
		}
		out.RevertURL, out.PersonMessage, out.Links = n.URL, n.Message, n.Links
	}
	out.Page.Items = make([]RevertPlanLine, 0, len(page.Items))
	for _, l := range page.Items {
		parsed, err := revert.ParseLine(l.Text)
		if err != nil {
			return RevertPlan{}, fmt.Errorf("guard returned a bad revert line %d: %w", l.No, err)
		}
		out.Page.Items = append(out.Page.Items, RevertPlanLine{RevertLine: l, Plan: parsed})
	}
	if out.PersonMessage, out.NextSteps, err = s.planGuidance(out); err != nil {
		return RevertPlan{}, err
	}
	return out, nil
}

// ApplyRevertBatchParams are apply_revert_batch's validated arguments.
type ApplyRevertBatchParams struct {
	RevertID uuid.UUID
	Lines    []int
}

// ApplyRevertBatch applies lines of a signed plan this agent prepared.
// Postgres checks them against the signed plan and re-checks each row.
func (s *Service) ApplyRevertBatch(ctx context.Context, p ApplyRevertBatchParams) (AppliedBatch, error) {
	res, err := s.Reverts.ApplyRevertBatch(ctx, p.RevertID, p.Lines)
	if err != nil {
		return AppliedBatch{}, err
	}
	out := AppliedBatch{BatchResult: res}
	if out.PersonMessage, out.NextSteps, err = s.batchGuidance(res); err != nil {
		return AppliedBatch{}, err
	}
	return out, nil
}

// AppliedBatch is one applied batch with what happens next (CONTRACT.md,
// Next steps): the next pending lines, or the end of the plan.
type AppliedBatch struct {
	guard.BatchResult
	PersonMessage string
	NextSteps     []mcp.NextStep
}

// RequestRevertParams are request_revert's validated arguments in its
// request form: one of the agent's own changes or runs, and why the person
// reverts it.
type RequestRevertParams struct {
	Scope  guard.RevertScope
	Intent string
}

// RequestedRevert is request_revert's answer in both forms: the revert as
// agent_reverts shows it, the link when one was issued, the line for the
// person and the agent's next steps (CONTRACT.md, Next steps).
type RequestedRevert struct {
	Revert        ledger.Revert
	RevertURL     string
	PersonMessage string
	Links         []mcp.Link
	NextSteps     []mcp.NextStep
}

func (s *Service) RequestRevert(ctx context.Context, p RequestRevertParams) (RequestedRevert, error) {
	if err := s.checkOwnScope(ctx, p.Scope); err != nil {
		return RequestedRevert{}, err
	}
	prep, err := s.Reverts.PrepareRevert(ctx, p.Scope, p.Intent, guard.MCPPrepareTimeout)
	if err != nil {
		return RequestedRevert{}, s.prepareError(ctx, toolRequestRevert, p.Scope, err)
	}
	r, err := s.Reverts.FindRevert(ctx, prep.RevertID)
	if err != nil {
		return RequestedRevert{}, err
	}
	return s.revertWithLink(ctx, r)
}

// revertWithLink issues r's link (revoking an earlier one) and returns it
// with the message that carries it: the REQUESTED steps, the person signs
// and the agent waits once.
func (s *Service) revertWithLink(ctx context.Context, r ledger.Revert) (RequestedRevert, error) {
	n, err := s.revertNotice(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	return RequestedRevert{Revert: r, RevertURL: n.URL, PersonMessage: n.Message, Links: n.Links, NextSteps: requestedSteps(r.ID, n.URL)}, nil
}

// DefaultRevertWait is how long request_revert with revertId waits for the
// person's signature when the agent names no waitForSignature, as the
// waiting write does.
const DefaultRevertWait = DefaultApprovalWait

// AwaitRevertParams is request_revert's wait form: a revert this agent
// requested, how long to wait for the person's signature, whether to issue
// a new link, and the person's signed code to deliver (nil for none).
type AwaitRevertParams struct {
	RevertID  uuid.UUID
	Wait      time.Duration
	Reissue   bool
	Signature *revert.Response
}

// AwaitRevert returns the state of a revert this agent requested. With a
// signature it delivers the person's code (Postgres verifies it) and
// returns at once; with Reissue on a PENDING revert it issues a new link
// and returns at once; otherwise it reads the revert about every s.Poll
// until it is not PENDING or Wait is over. Only a signature writes.
func (s *Service) AwaitRevert(ctx context.Context, p AwaitRevertParams) (RequestedRevert, error) {
	r, err := s.Reverts.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return RequestedRevert{}, revertNotFound(p.RevertID)
	}
	if err != nil {
		return RequestedRevert{}, err
	}
	switch {
	case p.Signature != nil:
		return s.deliverRevertSignature(ctx, r, *p.Signature)
	case p.Reissue && r.Status == ledger.RevertPending && r.Widened:
		// No link to the person's scope for the agent: the reissue resets the
		// revert to its proposal (owner, Q8).
		if r, err = s.resetToProposal(ctx, r); err != nil {
			return RequestedRevert{}, err
		}
		return s.revertWithLink(ctx, r)
	case p.Reissue && r.Status == ledger.RevertPending:
		if err := s.retirePersonScope(ctx, r); err != nil {
			return RequestedRevert{}, err
		}
		return s.revertWithLink(ctx, r)
	}
	err = s.awaitWhile(ctx, p.Wait, func() bool { return r.Status == ledger.RevertPending }, func(ctx context.Context) error {
		next, err := s.Reverts.FindRevert(ctx, r.ID)
		if err != nil {
			return err
		}
		r = next
		return nil
	})
	if err != nil {
		return RequestedRevert{}, err
	}
	return s.revertState(ctx, r)
}

// deliverRevertSignature submits the person's code for r, as basalt revert
// --apply does: the engine checks it names r and verifies against a
// registered passkey (for a clear refusal), then apply_revert verifies it in
// Postgres, which is the boundary.
func (s *Service) deliverRevertSignature(ctx context.Context, r ledger.Revert, code revert.Response) (RequestedRevert, error) {
	if err := s.checkRevertCode(ctx, r, code); err != nil {
		return RequestedRevert{}, err
	}
	if _, err := s.Reverts.ApplyRevert(ctx, r.ID, code.Assertion()); err != nil {
		return RequestedRevert{}, s.applyRevertError(ctx, r, err)
	}
	r, err := s.Reverts.FindRevert(ctx, r.ID)
	if err != nil {
		return RequestedRevert{}, err
	}
	return s.revertState(ctx, r)
}

func (s *Service) checkRevertCode(ctx context.Context, r ledger.Revert, code revert.Response) error {
	switch {
	case code.RevertID != r.ID:
		return s.badSignature(ctx, r, fmt.Sprintf("the code is for revert %s, not %s; nothing was reverted. The person signs "+
			"revert %s on its own page", code.RevertID, r.ID, r.ID))
	case r.Status == ledger.RevertExpired:
		return s.revertExpired(r)
	case r.Status != ledger.RevertPending:
		return alreadySigned(r)
	}
	keys, err := s.Approvals.Passkeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !bytes.Equal(k.ID, code.CredentialID) {
			continue
		}
		if _, err := revert.Verify(r.BindingText, k, code); err != nil {
			return s.badSignature(ctx, r, fmt.Sprintf("the code does not verify against the person's passkey, nothing was "+
				"reverted: %v", err))
		}
		return nil
	}
	return s.passkeyRevoked(ctx, r)
}

// applyRevertError gives Postgres's refusal of a code the engine let
// through its own steps: expired meanwhile, rows changed since the preview,
// or a signature only Postgres could judge.
func (s *Service) applyRevertError(ctx context.Context, r ledger.Revert, err error) error {
	code, ok := guard.CodeOf(err)
	if ok && code == guard.CodeRevertExpired {
		return s.revertExpired(r)
	}
	var pe *pgconn.PgError
	if !ok || code != guard.CodeRevertInvalid || !errors.As(err, &pe) {
		return err
	}
	// apply_revert's details (basalt_meta version 9) tell the cases apart.
	switch {
	case strings.Contains(pe.Detail, "rows changed since"):
		return s.rowsChanged(r, pe.Detail)
	case strings.Contains(pe.Detail, "passkey revoked"):
		return s.passkeyRevoked(ctx, r)
	case strings.Contains(pe.Detail, "already"):
		return alreadySigned(r)
	}
	return s.badSignature(ctx, r, "the database refused the code, nothing was reverted: "+pe.Detail)
}

// revertState is the answer for r without a new link: what happened, for
// the person, and the agent's next steps.
func (s *Service) revertState(ctx context.Context, r ledger.Revert) (RequestedRevert, error) {
	out := RequestedRevert{Revert: r}
	switch r.Status {
	case ledger.RevertApplied:
		out.PersonMessage = outcomeMessage(r)
		out.NextSteps = appliedSteps()
	case ledger.RevertApplying:
		// Nothing for the person yet: the agent restores the rest, and the
		// last batch tells them (CONTRACT.md, Next steps, APPLYING).
		out.NextSteps = applyingSteps(r.ID)
	case ledger.RevertExpired:
		out.PersonMessage = outcomeMessage(r)
		out.NextSteps = expiredSteps(r)
	default:
		what := "The revert of " + scopeText(r.Scope, r.ScopeID)
		return s.waitEnded(ctx, out, what)
	}
	return out, nil
}

// waitEnded is a PENDING answer after the wait: the person signs at the
// short link the agent gave them earlier (the engine keeps only its hash,
// and a lost one is reissued with reissueLink). Only when the engine serves
// no pages is there no short link, and the long link is given again.
func (s *Service) waitEnded(ctx context.Context, out RequestedRevert, what string) (RequestedRevert, error) {
	r := out.Revert
	expires := r.ExpiresAt.UTC().Format(personTime)
	if s.PagesOrigin != "" {
		out.PersonMessage = fmt.Sprintf("%s waits for your passkey at the short link the agent gave you, until %s. Tell the "+
			"agent when you have signed, or ask it for a new link if you lost that one.", what, expires)
		out.NextSteps = waitEndedSteps(r.ID, "", waitEndedShortLink)
		return out, nil
	}
	link, err := s.longRevertLink(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	out.PersonMessage = fmt.Sprintf("%s waits for your passkey at the link the agent gave you, until %s. Tell the agent "+
		"when you have signed, or give it the code the page shows.", what, expires)
	out.NextSteps = waitEndedSteps(r.ID, link, waitEndedLongLink)
	return out, nil
}

func applyByText(r ledger.Revert) string {
	if r.ApplyBy == nil {
		return "the deadline"
	}
	return r.ApplyBy.UTC().Format(personTime)
}

// checkOwnScope runs before any guard call on preview_revert and
// request_revert (RS-1, RS-6): the change, the run, or a task the agent ran
// in (any run with that task id) must be its own. Another agent's id and an
// unknown one get the same NOT_FOUND; Postgres refuses the same scopes when
// an agent role calls the guard directly.
func (s *Service) checkOwnScope(ctx context.Context, scope guard.RevertScope) error {
	switch scope.Kind {
	case revert.ScopeRun:
		_, err := s.Store.FindRun(ctx, scope.ID)
		if errors.Is(err, agentdb.ErrRunNotFound) {
			return notOwnScope(scope)
		}
		return err
	case revert.ScopeChange:
		own, err := s.Reverts.HasChange(ctx, scope.ID)
		return ownOr(own, err, notOwnScope(scope))
	case revert.ScopeTask:
		own, err := s.Reverts.HasTaskRun(ctx, scope.ID)
		return ownOr(own, err, notOwnTask(scope))
	}
	return &ArgumentError{Message: fmt.Sprintf("unknown revert scope %q", scope.Kind)}
}

// ownOr is checkOwnScope's answer to an ownership lookup: the lookup's
// error, refused when the scope is not the agent's, or nil.
func ownOr(own bool, err, refused error) error {
	if err != nil {
		return err
	}
	if !own {
		return refused
	}
	return nil
}

// taskWidenPointer ends every person message about a task the agent
// proposes (RS-1, RS-7): the same sentence whether or not other agents
// wrote in the task, so it tells the agent nothing it cannot see.
const taskWidenPointer = "You can include other agents' changes in this task on the signing page."

// notOwnScope is a change or run that is not this agent's (RS-6): NOT_FOUND
// with the scope's reason, the same answer for another agent's id and an
// unknown one, on preview_revert and request_revert alike.
func notOwnScope(scope guard.RevertScope) error {
	kind := strings.ToLower(string(scope.Kind))
	return &mcp.ToolError{Code: CodeNotFound, Reason: string(scope.Kind), Message: fmt.Sprintf(
		"%s %s is not one of this agent's %ss; nothing was prepared. An agent reverts only its own changes, runs and tasks it "+
			"ran in: check the id in run_history. If another agent's work looks wrong, ask that agent to request the revert; "+
			"a person can revert any change, run or task with basalt revert", kind, scope.ID, kind),
		NextSteps: []mcp.NextStep{callTool(toolListRuns, map[string]any{},
			"This id is not one of your runs or changes; list your runs.")}}
}

// notOwnTask is a task this agent has no run in (RS-6): NOT_FOUND reason
// TASK, the same answer whether or not other agents ran in it. The command
// leaves the agent for the person to fill in: this agent cannot see who ran
// in the task (N12-R1).
func notOwnTask(scope guard.RevertScope) error {
	return &mcp.ToolError{Code: CodeNotFound, Reason: string(revert.ScopeTask), Message: fmt.Sprintf(
		"task %s has no run of this agent; nothing was prepared. An agent reverts only its own work: "+
			"check the task id in list_runs", scope.ID),
		PersonMessage: fmt.Sprintf("This agent has no run in task %s. To revert work in that task, run "+
			"basalt revert --agent <agent> --task %s --open with an agent that ran in it, or ask that agent to request the revert.",
			scope.ID, scope.ID),
		NextSteps: []mcp.NextStep{callTool(toolListRuns, map[string]any{},
			"This task has none of your runs; list your runs.")}}
}

// scopeRefused answers a scope the guard refused (BS011, CONTRACT.md,
// Guard errors): another agent's or an unknown change, run or task is
// NOT_FOUND, alike; a descriptor the engine built badly is
// INVALID_ARGUMENT with the guard's explanation. nil when err is not a
// scope refusal.
func scopeRefused(scope guard.RevertScope, err error) error {
	detail, hint, ok := guard.ScopeRefusal(err)
	if !ok {
		return nil
	}
	switch detail {
	case guard.ScopeNotOwnChange, guard.ScopeNotOwnRun:
		return notOwnScope(scope)
	case guard.ScopeNotOwnTask:
		return notOwnTask(scope)
	}
	return &ArgumentError{Message: "the revert scope was refused: " + hint}
}

// prepareError is the answer to a prepare that failed: what the person
// can do when nothing can be reverted, or when the prepare is too large for
// an MCP call and their terminal is the better path.
func (s *Service) prepareError(ctx context.Context, tool string, scope guard.RevertScope, err error) error {
	if refused := scopeRefused(scope, err); refused != nil {
		return refused
	}
	if errors.Is(err, agentdb.ErrEmptyProposal) {
		return s.nothingToRevertError(ctx, tool, scope, reasonReadsOnly, "this agent changed no rows in it that a revert could restore")
	}
	if code, ok := guard.CodeOf(err); ok && code == guard.CodeNothingToRevert {
		return s.nothingToRevert(ctx, tool, scope, err)
	}
	if ctx.Err() != nil {
		// The client canceled the call: not the prepare's time limit.
		return fmt.Errorf("prepare revert: %w", ctx.Err())
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != sqlStateQueryCanceled {
		return err
	}
	return s.prepareTimeout(tool, scope, pe.Code)
}

// revertLink is what the agent hands the person to sign a prepared revert:
// the link chosen by the link budget and the message that carries it.
type revertLink struct {
	URL     string
	Message string
	Links   []mcp.Link
}

// revertNotice is the link to sign a prepared revert (chooseLink: a newly
// issued short link when this engine serves the pages, else the long one) and
// the message to show the person verbatim: the scope, what it restores and
// skips, why, the expiry, and for a large plan that they sign it once, then
// the link.
func (s *Service) revertNotice(ctx context.Context, r ledger.Revert) (revertLink, error) {
	long, err := s.longRevertLink(ctx, r)
	if err != nil {
		return revertLink{}, err
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return revertLink{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	short, err := s.shortLink(ctx, links.Revert, r.ID, r.ExpiresAt, issueLink)
	if err != nil {
		return revertLink{}, err
	}
	pick := chooseLink(short, long, s.LinkBudget)
	summary := fmt.Sprintf("Revert of %s %s: %d rows to restore, %d left as they are (changed after the agent). Why: %s. %s",
		strings.ToLower(string(b.Select.Scope)), b.Select.ScopeID, r.Rows, r.Skipped, shown(strings.TrimRight(b.Intent, ". "), maxIntentChars), expiryLine(r.ExpiresAt))
	var extra []string
	if b.Select.Scope == revert.ScopeTask {
		extra = append(extra, taskWidenPointer)
	}
	if r.Batched {
		extra = append(extra, fmt.Sprintf("It covers %d rows: you sign once, and the agent restores it in batches within %d hours.",
			b.Lines(), int(revert.ApplyWindow.Hours())))
	}
	msg, msgLinks := revertMessage(summary, pick, extra...)
	return revertLink{URL: pick.URL, Message: msg, Links: msgLinks}, nil
}
