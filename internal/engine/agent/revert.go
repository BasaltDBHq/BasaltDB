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
	FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error)
	RevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error)
	ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (guard.BatchResult, error)
	ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (guard.AppliedRevert, error)
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
}

// PreviewRevert returns what reverting the scope would restore and skip.
// It changes nothing: the guard runs the revert on trial and undoes it.
func (s *Service) PreviewRevert(ctx context.Context, p PreviewRevertParams) (RevertPreview, error) {
	texts, err := s.Reverts.PreviewRevert(ctx, p.Scope)
	if err != nil {
		return RevertPreview{}, s.previewError(ctx, p.Scope, err)
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
	return out, nil
}

// previewError answers a preview that failed. An id that is not this agent's
// stays NOT_FOUND; nothing to revert and a timeout carry their steps.
func (s *Service) previewError(ctx context.Context, scope guard.RevertScope, err error) error {
	if code, ok := guard.CodeOf(err); ok && code == guard.CodeNothingToRevert && scope.Kind != revert.ScopeTask {
		if ownErr := s.checkOwnScope(ctx, scope); ownErr != nil {
			return ownErr
		}
	}
	return s.prepareError(ctx, toolPreviewRevert, scope, err)
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
	return out, nil
}

// ApplyRevertBatchParams are apply_revert_batch's validated arguments.
type ApplyRevertBatchParams struct {
	RevertID uuid.UUID
	Lines    []int
}

// ApplyRevertBatch applies lines of a signed plan this agent prepared.
// Postgres checks them against the signed plan and re-checks each row.
func (s *Service) ApplyRevertBatch(ctx context.Context, p ApplyRevertBatchParams) (guard.BatchResult, error) {
	return s.Reverts.ApplyRevertBatch(ctx, p.RevertID, p.Lines)
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
	case p.Reissue && r.Status == ledger.RevertPending:
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
	what := fmt.Sprintf("The revert of %s %s", strings.ToLower(r.Scope), r.ScopeID)
	restored, skipped := r.Rows, r.Skipped
	if r.Batched {
		restored, skipped = r.Progress.Restored, r.Progress.Skipped
	}
	switch r.Status {
	case ledger.RevertApplied:
		out.PersonMessage = fmt.Sprintf("Reverted: %d rows restored, %d left as they are because someone changed them "+
			"after the agent (people win).", restored, skipped)
		out.NextSteps = appliedSteps()
	case ledger.RevertApplying:
		out.PersonMessage = fmt.Sprintf("You signed it. %s restores %d more rows in batches before %s (%d restored and %d "+
			"left as they are so far).", what, r.Progress.Pending, applyByText(r), restored, skipped)
		out.NextSteps = applyingSteps(r.ID)
	case ledger.RevertExpired:
		out.PersonMessage = fmt.Sprintf("%s expired at %s without your signature; nothing was reverted.", what,
			r.ExpiresAt.UTC().Format(personTime))
		if r.SignedAt != nil {
			out.PersonMessage = fmt.Sprintf("%s was signed but not finished by %s: %d rows restored, %d left as they are, "+
				"%d not restored.", what, applyByText(r), restored, skipped, r.Progress.Pending)
		}
		out.NextSteps = expiredSteps(r)
	default:
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

func (s *Service) checkOwnScope(ctx context.Context, scope guard.RevertScope) error {
	switch scope.Kind {
	case revert.ScopeRun:
		_, err := s.Store.FindRun(ctx, scope.ID)
		if errors.Is(err, agentdb.ErrRunNotFound) {
			return notOwnScope(scope)
		}
		return err
	case revert.ScopeChange:
		ok, err := s.Reverts.HasChange(ctx, scope.ID)
		if err != nil {
			return err
		}
		if !ok {
			return notOwnScope(scope)
		}
		return nil
	case revert.ScopeTask:
		return &ArgumentError{Message: taskScopeRefused}
	}
	return &ArgumentError{Message: fmt.Sprintf("unknown revert scope %q", scope.Kind)}
}

// taskScopeRefused explains why request_revert takes no task (N12-R7).
const taskScopeRefused = "request_revert has no taskId: a whole task is reverted only by the person (basalt revert --task). " +
	"Request the revert of one of your own changes (changeId) or runs (runId); if another agent's run looks wrong, ask that agent"

func notOwnScope(scope guard.RevertScope) error {
	kind := strings.ToLower(string(scope.Kind))
	return &mcp.ToolError{Code: CodeNotFound, Reason: string(scope.Kind), Message: fmt.Sprintf(
		"%s %s is not one of this agent's %ss; nothing was prepared. request_revert reverts only your own changes and runs: "+
			"check the id in run_history. If another agent's work looks wrong, ask that agent to request the revert; "+
			"a person can revert any change, run or task with basalt revert", kind, scope.ID, kind),
		NextSteps: []mcp.NextStep{callTool(toolListRuns, map[string]any{},
			"This id is not one of your runs or changes; list your runs.")}}
}

// prepareError is the answer to a prepare that failed: what the person
// can do when nothing can be reverted, or when the prepare is too large for
// an MCP call and their terminal is the better path.
func (s *Service) prepareError(ctx context.Context, tool string, scope guard.RevertScope, err error) error {
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
	short, err := s.shortLink(links.Revert, r.ID, r.ExpiresAt, issueLink)
	if err != nil {
		return revertLink{}, err
	}
	pick := chooseLink(short, long, s.LinkBudget)
	summary := fmt.Sprintf("Revert of %s %s: %d rows to restore, %d left as they are (changed after the agent). Why: %s. %s",
		strings.ToLower(string(b.Scope)), b.ScopeID, r.Rows, r.Skipped, shown(strings.TrimRight(b.Intent, ". "), maxIntentChars), expiryLine(r.ExpiresAt))
	var extra []string
	if r.Batched {
		extra = append(extra, fmt.Sprintf("It covers %d rows: you sign once, and the agent restores it in batches within %d hours.",
			b.Lines(), int(revert.ApplyWindow.Hours())))
	}
	msg, msgLinks := revertMessage(summary, pick, extra...)
	return revertLink{URL: pick.URL, Message: msg, Links: msgLinks}, nil
}
