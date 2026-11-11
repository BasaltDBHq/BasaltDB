package agent

import (
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
	if code, ok := guard.CodeOf(err); ok && code == guard.CodeNothingToRevert {
		return RevertPreview{}, &mcp.ToolError{Code: CodeNotFound, Message: fmt.Sprintf(
			"nothing to revert: %s %s changed no rows a revert could restore", p.Scope.Kind, p.Scope.ID)}
	}
	if err != nil {
		return RevertPreview{}, err
	}
	out := RevertPreview{Scope: p.Scope, Command: s.revertCommand(p.Scope)}
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
	start, err := lineAfter(texts, p.Cursor)
	if err != nil {
		return RevertPreview{}, err
	}
	end := min(start+p.Limit, len(lines))
	out.Page.Items = lines[start:end]
	if end < len(lines) {
		out.Page.NextCursor = pagination.EncodeNameCursor(lineHash(texts[end-1]))
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
		return 0, &ArgumentError{Message: "invalid cursor"}
	}
	for i, t := range texts {
		if lineHash(t) == hash {
			return i + 1, nil
		}
	}
	return 0, &ArgumentError{Message: "the cursor's line is no longer in the preview: the rows changed, start from the first page"}
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
}

// RevertPlan returns a large revert plan this agent prepared, its progress
// and one page of its lines, for the agent to apply with ApplyRevertBatch
// once the person signed it.
func (s *Service) RevertPlan(ctx context.Context, p RevertPlanParams) (RevertPlan, error) {
	r, err := s.Reverts.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return RevertPlan{}, &mcp.ToolError{Code: CodeNotFound, Message: fmt.Sprintf("no revert %s prepared by this agent", p.RevertID)}
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
		if out.RevertURL, out.PersonMessage, err = s.revertNotice(ctx, r); err != nil {
			return RevertPlan{}, err
		}
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

// revertCommand is what the person runs to revert the scope: it opens the
// revert page in their browser.
func (s *Service) revertCommand(scope guard.RevertScope) string {
	return fmt.Sprintf("basalt revert %s --%s %s --open", s.CLIFlags, strings.ToLower(string(scope.Kind)), scope.ID)
}

// RequestRevertParams are request_revert's validated arguments in its
// request form: one of the agent's own changes or runs, and why the person
// reverts it.
type RequestRevertParams struct {
	Scope  guard.RevertScope
	Intent string
}

// RequestedRevert is a revert prepared for the person to sign: its state,
// the link to sign it, one line to show the person verbatim, and what the
// agent does next.
type RequestedRevert struct {
	Revert        ledger.Revert
	Intent        string
	RevertURL     string
	PersonMessage string
	NextStep      string
}

// RequestRevert prepares a revert of one of the agent's own changes or
// runs, exactly as basalt revert does but within MCPPrepareTimeout, and
// issues the link the person signs it at. Nothing is reverted: Postgres
// applies it only with the person's passkey signature.
func (s *Service) RequestRevert(ctx context.Context, p RequestRevertParams) (RequestedRevert, error) {
	if err := s.checkOwnScope(ctx, p.Scope); err != nil {
		return RequestedRevert{}, err
	}
	prep, err := s.Reverts.PrepareRevert(ctx, p.Scope, p.Intent, guard.MCPPrepareTimeout)
	if err != nil {
		return RequestedRevert{}, s.prepareError(ctx, p.Scope, err)
	}
	r, err := s.Reverts.FindRevert(ctx, prep.RevertID)
	if err != nil {
		return RequestedRevert{}, err
	}
	link, msg, err := s.revertNotice(ctx, r)
	if err != nil {
		return RequestedRevert{}, err
	}
	next := nextStepAfterRequest
	if r.Batched {
		next = nextStepAfterBatchedRequest
	}
	return RequestedRevert{Revert: r, Intent: p.Intent, RevertURL: link, PersonMessage: msg, NextStep: next}, nil
}

// What the agent does after requesting a revert, while this engine cannot
// wait for the signature (request_revert's wait form is not served yet).
const (
	nextStepAfterRequest = "Show the person personMessage verbatim, then end your turn: this engine cannot wait for their signature yet " +
		"(do not call request_revert with revertId). When they say they signed, check run_history: the reverted changes show status REVERTED."
	nextStepAfterBatchedRequest = "Show the person personMessage verbatim, then end your turn: this engine cannot wait for their signature yet " +
		"(do not call request_revert with revertId). When they say they signed, call revert_plan with revertId, pending true and limit 200, " +
		"then apply_revert_batch with those line numbers, until pending is 0."
)

// AwaitRevertParams are request_revert's arguments in its wait form.
type AwaitRevertParams struct {
	RevertID uuid.UUID
}

// AwaitRevert is request_revert's wait form. This engine does not serve it
// yet: it always answers an error, NOT_FOUND for a revert the agent's role
// did not prepare, else what to do instead, and changes nothing.
func (s *Service) AwaitRevert(ctx context.Context, p AwaitRevertParams) error {
	_, err := s.Reverts.FindRevert(ctx, p.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return &mcp.ToolError{Code: CodeNotFound, Message: fmt.Sprintf(
			"no revert %s requested by this agent: request one with request_revert and a changeId or runId of yours", p.RevertID)}
	}
	if err != nil {
		return err
	}
	return &ArgumentError{Message: fmt.Sprintf(
		"this engine cannot wait for a revert's signature or take its code yet (request_revert with revertId comes in a later version); "+
			"nothing was changed. Do not call it again: end your turn, telling the person revert %s waits for their passkey at the link "+
			"you gave them. When they say they signed, check run_history (reverted changes show status REVERTED). If the page gave "+
			"them a basalt-revert.1. code, they apply it themselves with: basalt revert %s --apply <code>",
		p.RevertID, s.FullCLIFlags)}
}

// checkOwnScope refuses a scope that is not one of the agent's own changes
// or runs (N12-R7), read through the views that show the agent only its
// own: an agent requests reverts of its own work only. This is the
// engine's first filter; the person's signature remains the boundary.
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
	return &mcp.ToolError{Code: CodeNotFound, Message: fmt.Sprintf(
		"%s %s is not one of this agent's %ss; nothing was prepared. request_revert reverts only your own changes and runs: "+
			"check the id in run_history. If another agent's work looks wrong, ask that agent to request the revert; "+
			"a person can revert any change, run or task with basalt revert", kind, scope.ID, kind)}
}

// prepareError is the answer to a prepare that failed: what the person
// can do when nothing can be reverted, or when the prepare is too large for
// an MCP call and their terminal is the better path.
func (s *Service) prepareError(ctx context.Context, scope guard.RevertScope, err error) error {
	if code, ok := guard.CodeOf(err); ok && code == guard.CodeNothingToRevert {
		te := ToolError(err)
		te.Message = fmt.Sprintf("nothing to revert in %s %s: every row it wrote was changed after it (people win), or it wrote none; "+
			"nothing was prepared. preview_revert shows each row and why it is skipped. Tell the person; if the data still needs "+
			"fixing, suggest a forward fix. (%s)", strings.ToLower(string(scope.Kind)), scope.ID, te.Message)
		return te
	}
	if ctx.Err() != nil {
		// The client canceled the call: not the prepare's time limit.
		return fmt.Errorf("prepare revert: %w", ctx.Err())
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != sqlStateQueryCanceled {
		return err
	}
	return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonTimeLimit, SQLState: pe.Code, Message: fmt.Sprintf(
		"preparing the revert of %s %s took longer than the %d seconds an MCP call may take; nothing was prepared. "+
			"The person can prepare it in a terminal on the engine's machine, where it may take up to %d minutes. "+
			"Show them this command to run: %s",
		strings.ToLower(string(scope.Kind)), scope.ID, int(guard.MCPPrepareTimeout.Seconds()),
		int(guard.CLIPrepareTimeout.Minutes()), s.fullRevertCommand(scope))}
}

// fullRevertCommand is revertCommand naming the engine config even at its
// default path, for a command the person copies from a message as is.
func (s *Service) fullRevertCommand(scope guard.RevertScope) string {
	return fmt.Sprintf("basalt revert %s --%s %s --open", s.FullCLIFlags, strings.ToLower(string(scope.Kind)), scope.ID)
}

// revertNotice is the link to sign a prepared revert (a newly issued short
// link when this engine serves the pages, else the long one) and one line
// to show the person verbatim: the scope, what it restores and skips, why,
// the link and the expiry, and for a large plan that they sign it once.
func (s *Service) revertNotice(ctx context.Context, r ledger.Revert) (string, string, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return "", "", err
	}
	long, err := revert.Request{RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, CredentialIDs: ids}.URL(s.PagesBase)
	if err != nil {
		return "", "", err
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return "", "", fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	link, err := s.shortLink(links.Revert, r.ID, r.ExpiresAt, issueLink)
	if err != nil {
		return "", "", err
	}
	sign := "Review and sign with your passkey: " + link
	if link == "" {
		// No local pages: the page cannot send the signature back.
		link = long
		sign = fmt.Sprintf("Review and sign with your passkey: %s (the page then shows a code; apply it with: basalt revert %s --apply <code>)",
			long, s.FullCLIFlags)
	}
	msg := fmt.Sprintf("Revert of %s %s ready for your review: %d rows to restore, %d left as they are (changed after the agent). Why: %s. %s. Expires %s.",
		strings.ToLower(string(b.Scope)), b.ScopeID, r.Rows, r.Skipped, strings.TrimRight(b.Intent, ". "), sign, r.ExpiresAt.UTC().Format(personTime))
	if r.Batched {
		msg += fmt.Sprintf(" It covers %d rows: you sign it once, and the agent then restores it in batches within %d hours of your signature.",
			b.Lines(), int(revert.ApplyWindow.Hours()))
	}
	return link, msg, nil
}
