package revert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
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
	NextSteps     []toolresult.NextStep
}

// PreviewRevert returns what reverting the scope would restore and skip.
// It changes nothing: the guard runs the revert on trial and undoes it.
// The scope must be the agent's own (RS-1): another agent's id answers
// NOT_FOUND before any guard call.
func (rc *Service) PreviewRevert(ctx context.Context, p PreviewRevertParams) (RevertPreview, error) {
	if err := rc.checkOwnScope(ctx, p.Scope); err != nil {
		return RevertPreview{}, err
	}
	after, err := cursorHash(p.Cursor)
	if err != nil {
		return RevertPreview{}, err
	}
	pv, err := rc.store.Undo.PreviewRevert(ctx, p.Scope, after, p.Limit)
	if err != nil {
		return RevertPreview{}, rc.prepareError(ctx, guidance.ToolPreviewRevert, p.Scope, err)
	}
	if !pv.CursorFound {
		return RevertPreview{}, &guidance.ArgumentError{Message: "the cursor's line is no longer in the preview: the rows changed, start from the first page", Reason: guidance.ReasonStaleCursor}
	}
	if pv.Lines > 0 && pv.Restore == 0 {
		// Every line is skipped: nothing a revert could restore (AE-8, AE-14).
		return RevertPreview{}, rc.nothingToRevertError(ctx, guidance.ToolPreviewRevert, p.Scope, skipReason(pv), "every row is skipped")
	}
	out := RevertPreview{Scope: p.Scope, Rows: pv.Restore, Skipped: pv.Lines - pv.Restore}
	out.Page.Items = make([]revert.Line, 0, len(pv.Page))
	for _, pl := range pv.Page {
		l, err := revert.ParseMarkedLine(pl.Text)
		if err != nil {
			return RevertPreview{}, fmt.Errorf("guard returned a bad revert line: %w", err)
		}
		out.Page.Items = append(out.Page.Items, l.ForDisplay(rc.store.ShowValues))
	}
	if pv.More {
		out.Page.NextCursor = pagination.EncodeNameCursor(pv.Page[len(pv.Page)-1].Hash)
	}
	if out.PersonMessage, out.NextSteps, err = rc.previewGuidance(out); err != nil {
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
		return "", &guidance.ArgumentError{Message: "invalid cursor", Reason: guidance.ReasonStaleCursor}
	}
	return hash, nil
}

// RevertPlanLine is one line of a batched plan with its signed line
// parsed. Plan is nil on a widened plan's line that names a change the
// agent did not make: the agent's view leaves its text out (RS-5).
type RevertPlanLine struct {
	action.RevertLine
	Plan *revert.Line
}

// RevertPlan is a batched plan's state and one page of its lines; while
// the person has not signed it, the link to sign it and one line for them.
type RevertPlan struct {
	Revert    action.Revert
	Page      pagination.Page[RevertPlanLine]
	RevertURL string
	// RequestFile is the request beside a hash link in RevertURL.
	RequestFile   *links.RequestFile
	PersonMessage string
	NextSteps     []toolresult.NextStep
	Links         []toolresult.Link
	// tooLarge is set on a PENDING plan whose request no link this engine
	// has can carry (REQUEST_TOO_LARGE).
	tooLarge bool
}

// RevertPlan returns a large revert plan this agent prepared, its progress
// and one page of its lines, for the agent to apply with ApplyRevertBatch
// once the person signed it.
func (rc *Service) RevertPlan(ctx context.Context, p action.RevertLineParams) (RevertPlan, error) {
	r, err := rc.store.Records.FindRevert(ctx, p.RevertID)
	if refusalOf(err).Reason == action.RevertNotFound {
		return RevertPlan{}, &toolresult.ToolError{Code: guidance.CodeNotFound, Reason: guidance.ReasonRevert, Message: fmt.Sprintf("no revert %s prepared by this agent", p.RevertID)}
	}
	if err != nil {
		return RevertPlan{}, err
	}
	if !r.Batched {
		return RevertPlan{}, &guidance.ArgumentError{Message: fmt.Sprintf(
			"revert %s has %d lines: the revert page applies it in one call, there is no plan to apply in batches", r.ID, r.Rows+r.Skipped)}
	}
	page, err := rc.store.Records.RevertLines(ctx, p)
	if err != nil {
		return RevertPlan{}, err
	}
	out := RevertPlan{Revert: r, Page: pagination.Page[RevertPlanLine]{NextCursor: page.NextCursor}}
	if r.Status == action.RevertPending && !r.Widened {
		// A widened plan issues no link: the person signs on the page they
		// widened on (RS-5).
		n, err := rc.revertNotice(ctx, r)
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
			shown := parsed.ForDisplay(rc.store.ShowValues)
			line.Plan = &shown
		}
		out.Page.Items = append(out.Page.Items, line)
	}
	if out.PersonMessage, out.NextSteps, err = rc.planGuidance(out); err != nil {
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
// The store checks them against the signed plan and re-checks each row.
func (rc *Service) ApplyRevertBatch(ctx context.Context, p ApplyRevertBatchParams) (AppliedBatch, error) {
	res, err := rc.store.Undo.ApplyRevertBatch(ctx, p.RevertID, p.Lines)
	if err != nil {
		return AppliedBatch{}, err
	}
	out := AppliedBatch{BatchResult: res}
	if out.PersonMessage, out.NextSteps, err = rc.batchGuidance(res); err != nil {
		return AppliedBatch{}, err
	}
	return out, nil
}

// AppliedBatch is one applied batch with what happens next (CONTRACT.md,
// Next steps): the next pending lines, or the end of the plan.
type AppliedBatch struct {
	action.BatchResult
	PersonMessage string
	NextSteps     []toolresult.NextStep
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
	Revert    action.Revert
	RevertURL string
	// RequestFile is the request beside a hash link in RevertURL.
	RequestFile   *links.RequestFile
	PersonMessage string
	Links         []toolresult.Link
	NextSteps     []toolresult.NextStep
	// Receipt is the signed revert's receipt (APPLIED, APPLYING).
	Receipt *linksvc.Receipt
	// tooLarge is the notice when no link can carry the request.
	tooLarge revertLink
	// headline is the revert in one line, and issued is set when this
	// answer issued a new link: for the approval.deliver notice.
	headline string
	issued   bool
}

func (rc *Service) RequestRevert(ctx context.Context, p RequestRevertParams) (RequestedRevert, error) {
	if err := rc.checkOwnScope(ctx, p.Scope); err != nil {
		return RequestedRevert{}, err
	}
	prep, err := rc.store.Undo.PrepareRevert(ctx, p.Scope, p.Intent, rc.store.Limits.Prepare)
	if err != nil {
		return RequestedRevert{}, rc.prepareError(ctx, guidance.ToolRequestRevert, p.Scope, err)
	}
	r, err := rc.store.Records.FindRevert(ctx, prep.RevertID)
	if err != nil {
		return RequestedRevert{}, err
	}
	out, err := rc.revertWithLink(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if out.tooLarge.tooLarge {
		answer := rc.delivery.RevertTooLargeError(r.ID, out.tooLarge.cost, r.ExpiresAt)
		var te *toolresult.ToolError
		if errors.As(answer, &te) {
			// Prepared, with no link any page can open: a notice with none.
			out.RevertURL = ""
			rc.deliverRevert(linksvc.NoticeRevertRequested, out)
		}
		return RequestedRevert{}, answer
	}
	rc.deliverRevert(linksvc.NoticeRevertRequested, out)
	return out, nil
}

// prepareReissue readies a pending revert for a new link the agent asked
// for: a widened revert is reset to its proposal, since the agent gets no
// link to the person's scope (owner, Q8); otherwise the person's scope the
// engine still holds is retired (retirePersonScope). It returns the revert
// as it now stands.
func (rc *Service) prepareReissue(ctx context.Context, r action.Revert) (action.Revert, error) {
	if r.Widened {
		return rc.resetToProposal(ctx, r)
	}
	return r, rc.retirePersonScope(ctx, r)
}

// revertWithLink issues r's link (revoking an earlier one) and returns it
// with the message that carries it: the REQUESTED steps, the person signs
// and the agent waits once.
func (rc *Service) revertWithLink(ctx context.Context, r action.Revert) (RequestedRevert, error) {
	n, err := rc.revertNotice(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if n.tooLarge {
		// The results case REQUEST_TOO_LARGE (request_revert's reissue);
		// RequestRevert answers the error instead.
		steps, err := linksvc.RevertTooLargeSteps(r.ID, false)
		if err != nil {
			return RequestedRevert{}, err
		}
		return RequestedRevert{Revert: r, RevertURL: n.URL, PersonMessage: n.Message, NextSteps: steps, tooLarge: n, headline: n.Headline}, nil
	}
	rc.notifyRevert(ctx, r, n)
	return RequestedRevert{
		Revert: r, RevertURL: n.URL, RequestFile: n.File, PersonMessage: n.Message, Links: n.Links,
		NextSteps: guidance.WithSendRequest(requestedSteps(r.ID, n.URL, n.short == ""), n.File),
		headline:  n.Headline, issued: n.short != "",
	}, nil
}

// DefaultRevertWait is how long request_revert with revertId waits for the
// person's signature when the agent names no waitForSignature, as the
// waiting write does.
const DefaultRevertWait = guidance.DefaultApprovalWait

// AwaitRevertParams is request_revert's wait form: a revert this agent
// requested, how long to wait for the person's signature, and whether to
// issue a new link.
type AwaitRevertParams struct {
	RevertID uuid.UUID
	Wait     time.Duration
	Reissue  bool
}

// AwaitRevert returns the state of a revert this agent requested. With
// Reissue on a PENDING revert it issues a new link and returns at once;
// otherwise it reads the revert about every s.deps.Delivery.Poll until it is not PENDING
// or Wait is over. It never signs: the person signs on the revert page.
func (rc *Service) AwaitRevert(ctx context.Context, p AwaitRevertParams) (RequestedRevert, error) {
	r, err := rc.store.Records.FindRevert(ctx, p.RevertID)
	if refusalOf(err).Reason == action.RevertNotFound {
		return RequestedRevert{}, revertNotFound(p.RevertID)
	}
	if err != nil {
		return RequestedRevert{}, err
	}
	if p.Reissue && r.Status == action.RevertPending {
		r, err = rc.prepareReissue(ctx, r)
		if err != nil {
			return RequestedRevert{}, err
		}
		out, err := rc.revertWithLink(ctx, r)
		if err == nil && out.issued {
			rc.deliverRevert(linksvc.NoticeLinkReplaced, out)
		}
		return out, err
	}
	err = rc.delivery.AwaitWhile(ctx, p.Wait, func() bool { return r.Status == action.RevertPending }, func(ctx context.Context) error {
		// Each poll is one measured read with a budget of its own (as the
		// waiting write's).
		next, err := rc.store.Records.FindRevert(budget.With(ctx), r.ID)
		if err != nil {
			return err
		}
		r = next
		return nil
	})
	if err != nil {
		return RequestedRevert{}, err
	}
	return rc.revertState(ctx, r)
}

// applyRevertError gives the store's refusal of a signature the revert page
// relayed: expired meanwhile, rows changed since the preview, or a
// signature that does not verify.
func (rc *Service) applyRevertError(ctx context.Context, r action.Revert, err error) error {
	refused := refusalOf(err)
	switch refused.Reason {
	case action.RevertExpiredReason:
		return rc.revertExpired(r)
	case action.RevertNothing:
		return nothingSigned(r)
	case action.RevertRowsChanged:
		return rc.rowsChanged(r, refused.Detail)
	case action.RevertPasskeyRevoked:
		return rc.passkeyRevoked(ctx, r)
	case action.RevertAlreadySigned:
		return alreadySigned(r)
	case action.RevertSignature:
		return rc.badSignature(ctx, r, "the database refused the signature, nothing was reverted: "+refused.Detail)
	default:
		return err
	}
}

// refusalOf is the store's refusal in err, the zero refusal (no reason)
// when err carries none.
func refusalOf(err error) action.RevertRefusalError {
	if rr := action.RevertRefusalOf(err); rr != nil {
		return *rr
	}
	return action.RevertRefusalError{}
}

// revertState is the answer for r without a new link: what happened, for
// the person, and the agent's next steps. For a widened revert the person
// is told the agent cannot see what they added (RS-5).
func (rc *Service) revertState(ctx context.Context, r action.Revert) (RequestedRevert, error) {
	out, err := rc.revertStateOf(ctx, r)
	if err != nil {
		return out, err
	}
	if r.Widened {
		out.PersonMessage = strings.TrimSpace(widenedMessage + " " + out.PersonMessage)
	}
	if r.Status != action.RevertApplied && r.Status != action.RevertApplying {
		return out, nil
	}
	// A signed revert: its receipt, from the store's record, the line first
	// (CONTRACT.md, Vault channel, Receipts).
	receipt, err := rc.revertReceipt(r)
	if err != nil {
		return RequestedRevert{}, err
	}
	out.Receipt = &receipt
	out.PersonMessage = linksvc.WithReceiptLine(receipt.Line, out.PersonMessage)
	return out, nil
}

func (rc *Service) revertStateOf(ctx context.Context, r action.Revert) (RequestedRevert, error) {
	out := RequestedRevert{Revert: r}
	switch r.Status {
	case action.RevertApplied:
		out.PersonMessage = outcomeMessage(r)
		out.NextSteps = appliedSteps()
	case action.RevertApplying:
		// Nothing for the person yet: the agent restores the rest, and the
		// last batch tells them (CONTRACT.md, Next steps, APPLYING).
		out.NextSteps = applyingSteps(r.ID)
	case action.RevertExpired:
		out.PersonMessage = outcomeMessage(r)
		out.NextSteps = expiredSteps(r)
	case action.RevertRejected:
		out.PersonMessage = rejectedMessage(r)
		out.NextSteps = rejectedSteps()
	default:
		return rc.waitEnded(ctx, out, guidance.Sentence(revertTitle(r)))
	}
	return out, nil
}

// waitEnded is a PENDING answer after the wait: the person signs at the
// short link the agent gave them earlier (the engine keeps only its hash,
// and a lost one is reissued with reissueLink). Only when the engine serves
// no pages is there no short link, and the long link is given again.
func (rc *Service) waitEnded(ctx context.Context, out RequestedRevert, what string) (RequestedRevert, error) {
	r := out.Revert
	expires := r.ExpiresAt.UTC().Format(guidance.PersonTime)
	if r.Widened {
		// The person holds the only link to the scope they chose: the page
		// they widened on. The agent has none to give (RS-5).
		out.PersonMessage = fmt.Sprintf("%s waits for your passkey on the page where you changed the scope, until %s. Tell "+
			"the agent when you have signed.", what, expires)
		out.NextSteps = widenedWaitSteps(r.ID)
		return out, nil
	}
	link, err := rc.restatedRevertLink(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	if link.Kind == linksvc.LinkNone {
		steps, err := linksvc.RevertTooLargeSteps(r.ID, false)
		if err != nil {
			return RequestedRevert{}, err
		}
		out.RevertURL, out.PersonMessage, out.NextSteps = link.URL, rc.delivery.TooLargeMessage(what, linksvc.RevertRequestOf(r).Cost, r.ExpiresAt, true), steps
		return out, nil
	}
	if rc.delivery.ShortLinked(r.ID) || link.Kind == linksvc.LinkPage {
		out.PersonMessage = fmt.Sprintf("%s waits for your passkey at the short link the agent gave you, until %s. Tell the "+
			"agent when you have signed, or ask it for a new link if you lost that one.", what, expires)
		out.NextSteps = waitEndedSteps(r.ID, "", waitEndedShortLink)
		return out, nil
	}
	out.PersonMessage = fmt.Sprintf("%s waits until %s, but its link cannot be signed. Ask the agent for a new link later.", what, expires)
	out.NextSteps = waitEndedSteps(r.ID, link.URL, waitEndedLongLink)
	return out, nil
}

func applyByText(r action.Revert) string {
	if r.ApplyBy == nil {
		return "the deadline"
	}
	return r.ApplyBy.UTC().Format(guidance.PersonTime)
}

// checkOwnScope runs before any guard call on preview_revert and
// request_revert (RS-1, RS-6): the change, the run, or a task the agent ran
// in (any run with that task id) must be its own. Another agent's id and an
// unknown one get the same NOT_FOUND; the store refuses the same scopes when
// an agent role calls the guard directly.
func (rc *Service) checkOwnScope(ctx context.Context, scope action.Scope) error {
	switch scope.Kind {
	case revert.ScopeRun:
		_, err := rc.runs.FindRun(ctx, scope.ID)
		if errors.Is(err, action.ErrRunNotFound) {
			return notOwnScope(scope)
		}
		return err
	case revert.ScopeChange:
		own, err := rc.store.Records.HasChange(ctx, scope.ID)
		return ownOr(own, err, notOwnScope(scope))
	case revert.ScopeTask:
		own, err := rc.store.Records.HasTaskRun(ctx, scope.ID)
		return ownOr(own, err, notOwnTask(scope))
	}
	return &guidance.ArgumentError{Message: fmt.Sprintf("unknown revert scope %q", scope.Kind)}
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
	return &toolresult.ToolError{
		Code: guidance.CodeNotFound, Reason: string(scope.Kind), Message: fmt.Sprintf(
			"%s %s is not one of this agent's %ss; nothing was prepared. An agent reverts only its own changes, runs and tasks it "+
				"ran in: check the id in run_history. If another agent's work looks wrong, ask that agent to request the revert; "+
				"a person can revert any change, run or task on the revert page that agent's request opens", kind, scope.ID, kind),
		NextSteps: []toolresult.NextStep{guidance.CallTool(guidance.ToolListRuns, map[string]any{},
			"This id is not one of your runs or changes; list your runs.")},
	}
}

// notOwnTask is a task this agent has no run in (RS-6): NOT_FOUND reason
// TASK, the same answer whether or not other agents ran in it. The message
// names no agent: this agent cannot see who ran in the task (N12-R1).
func notOwnTask(scope action.Scope) error {
	return &toolresult.ToolError{
		Code: guidance.CodeNotFound, Reason: string(revert.ScopeTask), Message: fmt.Sprintf(
			"task %s has no run of this agent; nothing was prepared. An agent reverts only its own work: "+
				"check the task id in list_runs", scope.ID),
		PersonMessage: fmt.Sprintf("This agent has no run in task %s. To revert work in that task, ask an agent that ran in it "+
			"to request the revert: you can include the other agents' changes on its signing page.", scope.ID),
		NextSteps: []toolresult.NextStep{guidance.CallTool(guidance.ToolListRuns, map[string]any{},
			"This task has none of your runs; list your runs.")},
	}
}

// scopeRefused answers a scope the store refused (CONTRACT.md, Guard
// errors): another agent's or an unknown change, run or task is NOT_FOUND,
// alike; a descriptor the engine built badly is INVALID_ARGUMENT with the
// store's explanation. nil when refused is not about the scope.
func scopeRefused(scope action.Scope, refused action.RevertRefusalError) error {
	switch refused.Reason {
	case action.RevertNotOwnChange, action.RevertNotOwnRun:
		return notOwnScope(scope)
	case action.RevertNotOwnTask:
		return notOwnTask(scope)
	case action.RevertFilter:
		return scopeFilterRefused(refused.Detail)
	case action.RevertFilterName:
		return scopeFilterInvalid(refused.Detail)
	case action.RevertFilterCap:
		return ScopeFilterCapped()
	case action.RevertInvalid:
		return &guidance.ArgumentError{Message: "the revert scope was refused: " + refused.Detail}
	default:
		return nil
	}
}

// scopeFilterRefused answers runs or resources outside the agent's own
// work. refused is the store's list of refused entries, one fixed text per
// kind, so another agent's run or resource reads exactly like an unknown
// one.
func scopeFilterRefused(refused string) error {
	return &guidance.ArgumentError{Reason: guidance.ReasonScopeFilter, Message: "the revert filter names work that is not yours, nothing was " +
		"prepared: " + refused + ". runs lists only your own runs in the task, and resources only resources you wrote in this " +
		"scope; run_history shows them"}
}

// scopeFilterInvalid answers a resource name the store cannot use: the
// store's own text, never "not yours", since the name says nothing of
// whose work it is.
func scopeFilterInvalid(detail string) error {
	return &guidance.ArgumentError{Reason: guidance.ReasonScopeFilter, Message: "the revert filter is not valid, nothing was " +
		"prepared: " + detail}
}

func ScopeFilterCapped() error {
	return &guidance.ArgumentError{Reason: guidance.ReasonScopeFilterCap, Message: fmt.Sprintf("runs and resources each list at most %d "+
		"entries, nothing was prepared. Leave a filter out for all of your work in the scope: the person can narrow it on the "+
		"signing page", revert.MaxFilter)}
}

// prepareError is the answer to a prepare that failed: what the person
// can do when nothing can be reverted, or when the prepare is too large for
// an MCP call and their terminal is the better path.
func (rc *Service) prepareError(ctx context.Context, tool string, scope action.Scope, err error) error {
	refused := refusalOf(err)
	if out := scopeRefused(scope, refused); out != nil {
		return out
	}
	if errors.Is(err, action.ErrEmptyProposal) {
		return rc.nothingToRevertError(ctx, tool, scope, guidance.ReasonReadsOnly, "this agent changed no rows in it that a revert could restore")
	}
	if refused.Reason == action.RevertNothing || refused.Reason == action.RevertReadsOnly {
		return rc.nothingToRevert(ctx, tool, scope, refused)
	}
	if ctx.Err() != nil {
		// The client canceled the call: not the prepare's time limit.
		return fmt.Errorf("prepare revert: %w", ctx.Err())
	}
	if refused.Reason != action.RevertTimedOut {
		return err
	}
	return rc.prepareTimeout(tool, scope, refused.StoreCode)
}

// revertLink is what the agent hands the person to sign a prepared revert:
// the link chosen by the link budget and the message that carries it.
type revertLink struct {
	URL string
	// File is the request beside a hash link in URL; nil otherwise.
	File    *links.RequestFile
	Message string
	Links   []toolresult.Link
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
func (rc *Service) revertNotice(ctx context.Context, r action.Revert) (revertLink, error) {
	req := linksvc.RevertRequestOf(r)
	long, tooLarge, err := linksvc.LongOrTooLarge(req, func() (string, error) { return rc.longRevertLink(ctx, r) })
	if err != nil {
		return revertLink{}, err
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return revertLink{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	var short string
	if tooLarge {
		short, err = rc.delivery.LargeShortLink(ctx, links.Revert, r.ID, r.ExpiresAt, req.Cost)
	} else {
		short, err = rc.delivery.ShortLink(ctx, links.Revert, r.ID, r.ExpiresAt, linksvc.IssueLink)
	}
	if err != nil {
		return revertLink{}, err
	}
	if tooLarge && short == "" {
		return revertLink{
			URL: rc.delivery.PageAddress(links.Revert, r.ID), Headline: bindingHeadline(b, r), tooLarge: true, cost: req.Cost,
			Message: rc.delivery.TooLargeMessage(guidance.Sentence(revertTitle(r)), req.Cost, r.ExpiresAt, true),
		}, nil
	}
	pick, err := linksvc.ChooseLink(short, long, rc.core.LinkBudget, links.RevertFile(r.ID))
	if err != nil {
		return revertLink{}, err
	}
	headline := bindingHeadline(b, r)
	summary := fmt.Sprintf("%s Why: %s. %s", headline, guidance.Shown(strings.TrimRight(b.Intent, ". "), linksvc.MaxIntentChars), linksvc.ExpiryLine(r.ExpiresAt))
	var extra []string
	if b.Select.Scope == revert.ScopeTask {
		extra = append(extra, taskWidenPointer)
	}
	if r.Batched {
		extra = append(extra, fmt.Sprintf("It covers %d rows: you sign once, and the agent restores it in batches within %d hours.",
			b.Lines(), int(revert.ApplyWindow.Hours())))
	}
	msg, msgLinks := linksvc.RevertMessage(summary, pick, extra...)
	return revertLink{URL: pick.URL, File: pick.File, Message: msg, Links: msgLinks, Headline: headline, long: long, short: short}, nil
}

// bindingHeadline is the headline of a revert not widened, from its
// binding: the scope and filters it covers and its totals.
func bindingHeadline(b revert.Binding, r action.Revert) string {
	filters := filterText(action.Scope{Runs: b.Select.Runs, Tables: b.Select.Resources})
	return fmt.Sprintf("Revert of %s %s%s: %d rows to restore, %d left as they are (changed after the agent).",
		strings.ToLower(string(b.Select.Scope)), b.Select.ScopeID, filters, r.Rows, r.Skipped)
}

// widenedHeadline is the headline of a revert the person widened: totals
// only, no scope (RS-5, LP-3).
func widenedHeadline(r action.Revert) string {
	return fmt.Sprintf("Revert widened by the person: %d rows to restore.", r.Rows)
}

// revertHeadline is r's headline for list_pending and the person's
// notifications, built from what the store returned.
func revertHeadline(r action.Revert) (string, error) {
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
func (rc *Service) notifyRevert(ctx context.Context, r action.Revert, n revertLink) {
	sent := linksvc.RevertNotice{RevertID: r.ID, Agent: rc.core.Name, Headline: n.Headline, ExpiresAt: r.ExpiresAt, Widened: r.Widened}
	if !r.Widened {
		sent.Intent, sent.RevertURL, sent.ShortURL = r.Intent, n.long, n.short
	}
	if err := rc.delivery.NotifyRevertTo(context.WithoutCancel(ctx), sent); err != nil {
		rc.core.Log.Error("notify revert", "revertId", r.ID, "err", err)
	}
}
