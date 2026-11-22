package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// PreviewRevertParams are preview_revert's validated arguments: the scope
// (exactly one id) and a page of lines.
type PreviewRevertParams struct {
	pagination.Params
	Scope action.Scope
}

// RevertPreview is one page of what a revert would do, with the totals of
// the whole preview.
type RevertPreview struct {
	Scope   action.Scope
	Rows    int
	Skipped int
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
	after, err := cursorHash(p.Cursor)
	if err != nil {
		return RevertPreview{}, err
	}
	pv, err := s.Store.PreviewRevert(ctx, p.Scope, after, p.Limit)
	if err != nil {
		return RevertPreview{}, s.prepareError(ctx, toolPreviewRevert, p.Scope, err)
	}
	if !pv.CursorFound {
		return RevertPreview{}, &ArgumentError{Message: "the cursor's line is no longer in the preview: the rows changed, start from the first page", Reason: ReasonStaleCursor}
	}
	if pv.Lines > 0 && pv.Restore == 0 {
		// Every line is skipped: nothing a revert could restore (AE-8, AE-14).
		return RevertPreview{}, s.nothingToRevertError(ctx, toolPreviewRevert, p.Scope, skipReason(pv), "every row is skipped")
	}
	out := RevertPreview{Scope: p.Scope, Rows: pv.Restore, Skipped: pv.Lines - pv.Restore}
	out.Page.Items = make([]revert.Line, 0, len(pv.Page))
	for _, pl := range pv.Page {
		l, err := revert.ParseMarkedLine(pl.Text)
		if err != nil {
			return RevertPreview{}, fmt.Errorf("guard returned a bad revert line: %w", err)
		}
		out.Page.Items = append(out.Page.Items, l.ForDisplay())
	}
	if pv.More {
		out.Page.NextCursor = pagination.EncodeNameCursor(pv.Page[len(pv.Page)-1].Hash)
	}
	if out.PersonMessage, out.NextSteps, err = s.previewGuidance(out); err != nil {
		return RevertPreview{}, err
	}
	return out, nil
}

// cursorHash is the hash of the line a preview cursor names ("" for the
// first page). The cursor names a line by the hash of its signed text
// (keyset on the signed line order), so a preview that changed between
// pages is refused rather than skipped over.
func cursorHash(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	hash, err := pagination.DecodeNameCursor(cursor)
	if err != nil || hash == "" {
		return "", &ArgumentError{Message: "invalid cursor", Reason: ReasonStaleCursor}
	}
	return hash, nil
}

// RevertPlanParams are revert_plan's validated arguments: a batched plan
// and one page of its lines (only pending ones with Outcome PENDING).
type RevertPlanParams = ledger.RevertLineParams

// RevertPlanLine is one line of a batched plan with its signed line
// parsed. Plan is nil on a widened plan's line that names a change the
// agent did not make: the agent's view leaves its text out (RS-5).
type RevertPlanLine struct {
	ledger.RevertLine
	Plan *revert.Line
}

// RevertPlan is a batched plan's state and one page of its lines; while
// the person has not signed it, the link to sign it and one line for them.
type RevertPlan struct {
	Revert    ledger.Revert
	Page      pagination.Page[RevertPlanLine]
	RevertURL string
	// RequestFile is the request beside a hash link in RevertURL.
	RequestFile   *links.RequestFile
	PersonMessage string
	NextSteps     []mcp.NextStep
	Links         []mcp.Link
	// tooLarge is set on a PENDING plan whose request no link this engine
	// has can carry (REQUEST_TOO_LARGE).
	tooLarge bool
}

// RevertPlan returns a large revert plan this agent prepared, its progress
// and one page of its lines, for the agent to apply with ApplyRevertBatch
// once the person signed it.
func (s *Service) RevertPlan(ctx context.Context, p RevertPlanParams) (RevertPlan, error) {
	r, err := s.Store.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return RevertPlan{}, &mcp.ToolError{Code: CodeNotFound, Reason: reasonRevert, Message: fmt.Sprintf("no revert %s prepared by this agent", p.RevertID)}
	}
	if err != nil {
		return RevertPlan{}, err
	}
	if !r.Batched {
		return RevertPlan{}, &ArgumentError{Message: fmt.Sprintf(
			"revert %s has %d lines: the revert page applies it in one call, there is no plan to apply in batches", r.ID, r.Rows+r.Skipped)}
	}
	page, err := s.Store.RevertLines(ctx, p)
	if err != nil {
		return RevertPlan{}, err
	}
	out := RevertPlan{Revert: r, Page: pagination.Page[RevertPlanLine]{NextCursor: page.NextCursor}}
	if r.Status == ledger.RevertPending && !r.Widened {
		// A widened plan issues no link: the person signs on the page they
		// widened on (RS-5).
		n, err := s.revertNotice(ctx, r)
		if err != nil {
			return RevertPlan{}, err
		}
		out.RevertURL, out.RequestFile, out.PersonMessage, out.Links = n.URL, n.File, n.Message, n.Links
		out.tooLarge = n.tooLarge
	}
	out.Page.Items = make([]RevertPlanLine, 0, len(page.Items))
	for _, l := range page.Items {
		line := RevertPlanLine{RevertLine: l}
		if l.Text != "" {
			parsed, err := revert.ParseMarkedLine(l.Text)
			if err != nil {
				return RevertPlan{}, fmt.Errorf("guard returned a bad revert line %d: %w", l.No, err)
			}
			shown := parsed.ForDisplay()
			line.Plan = &shown
		}
		out.Page.Items = append(out.Page.Items, line)
	}
	if out.PersonMessage, out.NextSteps, err = s.planGuidance(out); err != nil {
		return RevertPlan{}, err
	}
	if r.Widened {
		out.PersonMessage = strings.TrimSpace(widenedMessage + " " + out.PersonMessage)
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
	res, err := s.Store.ApplyRevertBatch(ctx, p.RevertID, p.Lines)
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
	action.BatchResult
	PersonMessage string
	NextSteps     []mcp.NextStep
}

// RequestRevertParams are request_revert's validated arguments in its
// request form: one of the agent's own changes or runs, and why the person
// reverts it.
type RequestRevertParams struct {
	Scope  action.Scope
	Intent string
}

// RequestedRevert is request_revert's answer in both forms: the revert as
// agent_reverts shows it, the link when one was issued, the line for the
// person and the agent's next steps (CONTRACT.md, Next steps).
type RequestedRevert struct {
	Revert    ledger.Revert
	RevertURL string
	// RequestFile is the request beside a hash link in RevertURL.
	RequestFile   *links.RequestFile
	PersonMessage string
	Links         []mcp.Link
	NextSteps     []mcp.NextStep
	// Receipt is the signed revert's receipt (APPLIED, APPLYING).
	Receipt *Receipt
	// tooLarge is the notice when no link can carry the request.
	tooLarge revertLink
	// headline is the revert in one line, and issued is set when this
	// answer issued a new link: for the approval.deliver notice.
	headline string
	issued   bool
}

func (s *Service) RequestRevert(ctx context.Context, p RequestRevertParams) (RequestedRevert, error) {
	if err := s.checkOwnScope(ctx, p.Scope); err != nil {
		return RequestedRevert{}, err
	}
	prep, err := s.Store.PrepareRevert(ctx, p.Scope, p.Intent, guard.MCPPrepareTimeout)
	if err != nil {
		return RequestedRevert{}, s.prepareError(ctx, toolRequestRevert, p.Scope, err)
	}
	r, err := s.Store.FindRevert(ctx, prep.RevertID)
	if err != nil {
		return RequestedRevert{}, err
	}
	out, err := s.revertWithLink(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if out.tooLarge.tooLarge {
		answer := s.revertTooLargeError(r.ID, out.tooLarge.cost, r.ExpiresAt)
		var te *mcp.ToolError
		if errors.As(answer, &te) {
			// Prepared, with no link any page can open: a notice with none.
			out.RevertURL = ""
			s.deliverRevert(NoticeRevertRequested, out)
		}
		return RequestedRevert{}, answer
	}
	s.deliverRevert(NoticeRevertRequested, out)
	return out, nil
}

// prepareReissue readies a pending revert for a new link the agent asked
// for: a widened revert is reset to its proposal, since the agent gets no
// link to the person's scope (owner, Q8); otherwise the person's scope the
// engine still holds is retired (retirePersonScope). It returns the revert
// as it now stands.
func (s *Service) prepareReissue(ctx context.Context, r ledger.Revert) (ledger.Revert, error) {
	if r.Widened {
		return s.resetToProposal(ctx, r)
	}
	return r, s.retirePersonScope(ctx, r)
}

// revertWithLink issues r's link (revoking an earlier one) and returns it
// with the message that carries it: the REQUESTED steps, the person signs
// and the agent waits once.
func (s *Service) revertWithLink(ctx context.Context, r ledger.Revert) (RequestedRevert, error) {
	n, err := s.revertNotice(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if n.tooLarge {
		// The results case REQUEST_TOO_LARGE (request_revert's reissue);
		// RequestRevert answers the error instead.
		steps, err := revertTooLargeSteps(r.ID, false)
		if err != nil {
			return RequestedRevert{}, err
		}
		return RequestedRevert{Revert: r, RevertURL: n.URL, PersonMessage: n.Message, NextSteps: steps, tooLarge: n, headline: n.Headline}, nil
	}
	s.notifyRevert(ctx, r, n)
	return RequestedRevert{
		Revert: r, RevertURL: n.URL, RequestFile: n.File, PersonMessage: n.Message, Links: n.Links,
		NextSteps: withSendRequest(requestedSteps(r.ID, n.URL), n.File),
		headline:  n.Headline, issued: n.short != "",
	}, nil
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
	r, err := s.Store.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return RequestedRevert{}, revertNotFound(p.RevertID)
	}
	if err != nil {
		return RequestedRevert{}, err
	}
	switch {
	case p.Signature != nil:
		return s.deliverRevertSignature(ctx, r, *p.Signature)
	case p.Reissue && r.Status == ledger.RevertPending:
		r, err = s.prepareReissue(ctx, r)
		if err != nil {
			return RequestedRevert{}, err
		}
		out, err := s.revertWithLink(ctx, r)
		if err == nil && out.issued {
			s.deliverRevert(NoticeLinkReplaced, out)
		}
		return out, err
	}
	err = s.awaitWhile(ctx, p.Wait, func() bool { return r.Status == ledger.RevertPending }, func(ctx context.Context) error {
		// Each poll is one measured read with a budget of its own (as the
		// waiting write's).
		next, err := s.Store.FindRevert(resultsize.With(ctx), r.ID)
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
// Postgres, which is the boundary. For a widened revert the agent role
// cannot read the binding, so only Postgres verifies the signature.
func (s *Service) deliverRevertSignature(ctx context.Context, r ledger.Revert, code revert.Response) (RequestedRevert, error) {
	if err := s.checkRevertCode(ctx, r, code); err != nil {
		return RequestedRevert{}, err
	}
	if _, err := s.Store.ApplyRevert(ctx, r.ID, code.Assertion()); err != nil {
		return RequestedRevert{}, s.applyRevertError(ctx, r, err)
	}
	r, err := s.Store.FindRevert(ctx, r.ID)
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
	keys, err := s.Store.Passkeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if !bytes.Equal(k.ID, code.CredentialID) {
			continue
		}
		if r.Widened {
			// The agent's view hides a widened revert's binding (RS-5):
			// apply_revert verifies the signature, and applyRevertError maps
			// its refusal to the same answers.
			return nil
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
	code, ok := ledgerCode(err)
	switch {
	case ok && code == guard.CodeRevertExpired:
		return s.revertExpired(r)
	case ok && code == guard.CodeNothingToRevert:
		return nothingSigned(r)
	}
	if !ok || code != guard.CodeRevertInvalid {
		return err
	}
	// apply_revert's details (basalt_meta version 9) tell the cases apart.
	detail := storeDetail(err)
	switch {
	case strings.Contains(detail, "rows changed since"):
		return s.rowsChanged(r, detail)
	case strings.Contains(detail, "passkey revoked"):
		return s.passkeyRevoked(ctx, r)
	case strings.Contains(detail, "already"):
		return alreadySigned(r)
	}
	return s.badSignature(ctx, r, "the database refused the code, nothing was reverted: "+detail)
}

// revertState is the answer for r without a new link: what happened, for
// the person, and the agent's next steps. For a widened revert the person
// is told the agent cannot see what they added (RS-5).
func (s *Service) revertState(ctx context.Context, r ledger.Revert) (RequestedRevert, error) {
	out, err := s.revertStateOf(ctx, r)
	if err != nil {
		return out, err
	}
	if r.Widened {
		out.PersonMessage = strings.TrimSpace(widenedMessage + " " + out.PersonMessage)
	}
	if r.Status != ledger.RevertApplied && r.Status != ledger.RevertApplying {
		return out, nil
	}
	// A signed revert: its receipt, from Postgres's record, the line first
	// (CONTRACT.md, Vault channel, Receipts).
	receipt, err := s.revertReceipt(r)
	if err != nil {
		return RequestedRevert{}, err
	}
	out.Receipt = &receipt
	out.PersonMessage = withReceiptLine(receipt.Line, out.PersonMessage)
	return out, nil
}

func (s *Service) revertStateOf(ctx context.Context, r ledger.Revert) (RequestedRevert, error) {
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
	case ledger.RevertRejected:
		out.PersonMessage = rejectedMessage(r)
		out.NextSteps = rejectedSteps()
	default:
		return s.waitEnded(ctx, out, sentence(revertTitle(r)))
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
	if r.Widened {
		// The person holds the only link to the scope they chose: the page
		// they widened on. The agent has none to give (RS-5).
		out.PersonMessage = fmt.Sprintf("%s waits for your passkey on the page where you changed the scope, until %s. Tell "+
			"the agent when you have signed.", what, expires)
		out.NextSteps = widenedWaitSteps(r.ID)
		return out, nil
	}
	link, err := s.restatedRevertLink(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if link.Kind == linkNone {
		steps, err := revertTooLargeSteps(r.ID, false)
		if err != nil {
			return RequestedRevert{}, err
		}
		out.RevertURL, out.PersonMessage, out.NextSteps = link.URL, s.tooLargeMessage(what, revertRequestOf(r).Cost, r.ExpiresAt, true), steps
		return out, nil
	}
	if s.PagesOrigin != "" || link.Kind == linkPage {
		out.PersonMessage = fmt.Sprintf("%s waits for your passkey at the short link the agent gave you, until %s. Tell the "+
			"agent when you have signed, or ask it for a new link if you lost that one.", what, expires)
		out.NextSteps = waitEndedSteps(r.ID, "", waitEndedShortLink)
		return out, nil
	}
	out.PersonMessage = fmt.Sprintf("%s waits for your passkey at the link the agent gave you, until %s. Tell the agent "+
		"when you have signed, or give it the code the page shows.", what, expires)
	out.NextSteps = waitEndedSteps(r.ID, link.URL, waitEndedLongLink)
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
func (s *Service) checkOwnScope(ctx context.Context, scope action.Scope) error {
	switch scope.Kind {
	case revert.ScopeRun:
		_, err := s.Store.FindRun(ctx, scope.ID)
		if errors.Is(err, action.ErrRunNotFound) {
			return notOwnScope(scope)
		}
		return err
	case revert.ScopeChange:
		own, err := s.Store.HasChange(ctx, scope.ID)
		return ownOr(own, err, notOwnScope(scope))
	case revert.ScopeTask:
		own, err := s.Store.HasTaskRun(ctx, scope.ID)
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
func notOwnScope(scope action.Scope) error {
	kind := strings.ToLower(string(scope.Kind))
	return &mcp.ToolError{
		Code: CodeNotFound, Reason: string(scope.Kind), Message: fmt.Sprintf(
			"%s %s is not one of this agent's %ss; nothing was prepared. An agent reverts only its own changes, runs and tasks it "+
				"ran in: check the id in run_history. If another agent's work looks wrong, ask that agent to request the revert; "+
				"a person can revert any change, run or task on the revert page that agent's request opens", kind, scope.ID, kind),
		NextSteps: []mcp.NextStep{callTool(toolListRuns, map[string]any{},
			"This id is not one of your runs or changes; list your runs.")},
	}
}

// notOwnTask is a task this agent has no run in (RS-6): NOT_FOUND reason
// TASK, the same answer whether or not other agents ran in it. The message
// names no agent: this agent cannot see who ran in the task (N12-R1).
func notOwnTask(scope action.Scope) error {
	return &mcp.ToolError{
		Code: CodeNotFound, Reason: string(revert.ScopeTask), Message: fmt.Sprintf(
			"task %s has no run of this agent; nothing was prepared. An agent reverts only its own work: "+
				"check the task id in list_runs", scope.ID),
		PersonMessage: fmt.Sprintf("This agent has no run in task %s. To revert work in that task, ask an agent that ran in it "+
			"to request the revert: you can include the other agents' changes on its signing page.", scope.ID),
		NextSteps: []mcp.NextStep{callTool(toolListRuns, map[string]any{},
			"This task has none of your runs; list your runs.")},
	}
}

// scopeRefused answers a scope the guard refused (BS011, CONTRACT.md,
// Guard errors): another agent's or an unknown change, run or task is
// NOT_FOUND, alike; a descriptor the engine built badly is
// INVALID_ARGUMENT with the guard's explanation. nil when err is not a
// scope refusal.
func scopeRefused(scope action.Scope, err error) error {
	detail, hint, ok := scopeRefusal(err)
	if !ok {
		return nil
	}
	switch detail {
	case guard.ScopeNotOwnChange, guard.ScopeNotOwnRun:
		return notOwnScope(scope)
	case guard.ScopeNotOwnTask:
		return notOwnTask(scope)
	case guard.ScopeFilter:
		return scopeFilterRefused(hint)
	case guard.ScopeFilterCap:
		return scopeFilterCapped()
	}
	return &ArgumentError{Message: "the revert scope was refused: " + hint}
}

// scopeFilterRefused answers runs or tables outside the agent's own work.
// refused is the guard's list of refused entries, one fixed text per kind,
// so another agent's run or table reads exactly like an unknown one.
func scopeFilterRefused(refused string) error {
	return &ArgumentError{Reason: ReasonScopeFilter, Message: "the revert filter names work that is not yours, nothing was " +
		"prepared: " + refused + ". runs lists only your own runs in the task, and tables only tables you wrote in this " +
		"scope; run_history shows them"}
}

func scopeFilterCapped() error {
	return &ArgumentError{Reason: ReasonScopeFilterCap, Message: fmt.Sprintf("runs and tables each list at most %d "+
		"entries, nothing was prepared. Leave a filter out for all of your work in the scope: the person can narrow it on the "+
		"signing page", revert.MaxFilter)}
}

// prepareError is the answer to a prepare that failed: what the person
// can do when nothing can be reverted, or when the prepare is too large for
// an MCP call and their terminal is the better path.
func (s *Service) prepareError(ctx context.Context, tool string, scope action.Scope, err error) error {
	if refused := scopeRefused(scope, err); refused != nil {
		return refused
	}
	if errors.Is(err, action.ErrEmptyProposal) {
		return s.nothingToRevertError(ctx, tool, scope, reasonReadsOnly, "this agent changed no rows in it that a revert could restore")
	}
	if code, ok := ledgerCode(err); ok && code == guard.CodeNothingToRevert {
		return s.nothingToRevert(ctx, tool, scope, err)
	}
	if ctx.Err() != nil {
		// The client canceled the call: not the prepare's time limit.
		return fmt.Errorf("prepare revert: %w", ctx.Err())
	}
	if !timedOut(err) {
		return err
	}
	return s.prepareTimeout(tool, scope, storeError(err).SQLState)
}

// revertLink is what the agent hands the person to sign a prepared revert:
// the link chosen by the link budget and the message that carries it.
type revertLink struct {
	URL string
	// File is the request beside a hash link in URL; nil otherwise.
	File    *links.RequestFile
	Message string
	Links   []mcp.Link
	// Headline is the revert in one line (revertHeadline); long and short
	// are its two links, for the person's notification.
	Headline    string
	long, short string
	// tooLarge is set when no link this engine has can carry the request
	// (REQUEST_TOO_LARGE): URL is then the page's address with no fragment,
	// Message says what the person changes, and Cost is what its lines cost.
	tooLarge bool
	cost     int64
}

// revertNotice is the link to sign a prepared revert (chooseLink: a newly
// issued short link when this engine serves the pages, else the long one) and
// the message to show the person verbatim: the scope, what it restores and
// skips, why, the expiry, and for a large plan that they sign it once, then
// the link.
func (s *Service) revertNotice(ctx context.Context, r ledger.Revert) (revertLink, error) {
	req := revertRequestOf(r)
	long, tooLarge, err := longOrTooLarge(req, func() (string, error) { return s.longRevertLink(ctx, r) })
	if err != nil {
		return revertLink{}, err
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return revertLink{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	var short string
	if tooLarge {
		short, err = s.largeShortLink(ctx, links.Revert, r.ID, r.ExpiresAt, req.Cost)
	} else {
		short, err = s.shortLink(ctx, links.Revert, r.ID, r.ExpiresAt, issueLink)
	}
	if err != nil {
		return revertLink{}, err
	}
	if tooLarge && short == "" {
		return revertLink{
			URL: s.pageAddress(links.Revert, r.ID), Headline: bindingHeadline(b, r), tooLarge: true, cost: req.Cost,
			Message: s.tooLargeMessage(sentence(revertTitle(r)), req.Cost, r.ExpiresAt, true),
		}, nil
	}
	pick, err := chooseLink(short, long, s.LinkBudget, links.RevertFile(r.ID))
	if err != nil {
		return revertLink{}, err
	}
	headline := bindingHeadline(b, r)
	summary := fmt.Sprintf("%s Why: %s. %s", headline, shown(strings.TrimRight(b.Intent, ". "), maxIntentChars), expiryLine(r.ExpiresAt))
	var extra []string
	if b.Select.Scope == revert.ScopeTask {
		extra = append(extra, taskWidenPointer)
	}
	if r.Batched {
		extra = append(extra, fmt.Sprintf("It covers %d rows: you sign once, and the agent restores it in batches within %d hours.",
			b.Lines(), int(revert.ApplyWindow.Hours())))
	}
	msg, msgLinks := revertMessage(summary, pick, extra...)
	return revertLink{URL: pick.URL, File: pick.File, Message: msg, Links: msgLinks, Headline: headline, long: long, short: short}, nil
}

// bindingHeadline is the headline of a revert not widened, from its
// binding: the scope and filters it covers and its totals.
func bindingHeadline(b revert.Binding, r ledger.Revert) string {
	filters := filterText(action.Scope{Runs: b.Select.Runs, Tables: b.Select.Tables})
	return fmt.Sprintf("Revert of %s %s%s: %d rows to restore, %d left as they are (changed after the agent).",
		strings.ToLower(string(b.Select.Scope)), b.Select.ScopeID, filters, r.Rows, r.Skipped)
}

// widenedHeadline is the headline of a revert the person widened: totals
// only, no scope (RS-5, LP-3).
func widenedHeadline(r ledger.Revert) string {
	return fmt.Sprintf("Revert widened by the person: %d rows to restore.", r.Rows)
}

// revertHeadline is r's headline for list_pending and the person's
// notifications, built from what Postgres returned.
func revertHeadline(r ledger.Revert) (string, error) {
	if r.Widened {
		return widenedHeadline(r), nil
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return "", fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	return bindingHeadline(b, r), nil
}

// notifyRevert tells the person, through the Notifier, that r waits
// for their signature (LP-2). A failed notice is logged; it never fails the
// call.
func (s *Service) notifyRevert(ctx context.Context, r ledger.Revert, n revertLink) {
	sent := RevertNotice{RevertID: r.ID, Agent: s.Name, Headline: n.Headline, ExpiresAt: r.ExpiresAt, Widened: r.Widened}
	if !r.Widened {
		sent.Intent, sent.RevertURL, sent.ShortURL = r.Intent, n.long, n.short
	}
	if err := s.Notifier.NotifyRevert(context.WithoutCancel(ctx), sent); err != nil {
		s.Log.Error("notify revert", "revertId", r.ID, "err", err)
	}
}
