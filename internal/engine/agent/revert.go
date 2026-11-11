package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
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

// revertNotice is the link to sign a prepared revert (short when this
// engine serves the pages) and one line to show the person verbatim.
func (s *Service) revertNotice(ctx context.Context, r ledger.Revert) (string, string, error) {
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return "", "", err
	}
	long, err := revert.Request{RevertID: r.ID, Binding: r.BindingText, Lines: r.Lines, CredentialIDs: ids}.URL(s.revertPage())
	if err != nil {
		return "", "", err
	}
	link := s.shortLink(revertPath, r.ID, long)
	msg := fmt.Sprintf("A revert is waiting for your passkey: %d rows to restore, %d left as they are. Review and sign: %s. Expires %s.",
		r.Rows, r.Skipped, link, r.ExpiresAt.UTC().Format(personTime))
	return link, msg, nil
}

// revertPage is the revert page next to the approval page (web/revert).
func (s *Service) revertPage() string {
	base, err := url.Parse(s.ApprovalPage)
	if err != nil {
		return revert.PageURL
	}
	return base.ResolveReference(&url.URL{Path: "../revert/"}).String()
}
