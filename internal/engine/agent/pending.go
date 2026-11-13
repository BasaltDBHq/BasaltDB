package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// Kinds of list_pending items (owner decision LP-1).
const (
	KindApproval = "APPROVAL"
	KindRevert   = "REVERT"
)

// PendingParams are list_pending's validated arguments: one page over held
// writes and reverts, keyset on the id (UUIDv7, so time order). RunID
// filters held writes and lists no revert; Status "" lists every open
// state.
type PendingParams struct {
	pagination.Params
	Kind    string
	RunID   uuid.UUID
	Status  string
	Reissue bool
}

// PendingEntry is one list_pending item: exactly one of Approval and
// Revert is set.
type PendingEntry struct {
	Approval *PendingItem
	Revert   *PendingRevert
}

func (e PendingEntry) id() uuid.UUID {
	if e.Approval != nil {
		return e.Approval.ID
	}
	return e.Revert.ID
}

// PendingRevert is one open revert with what the agent hands the person:
// its headline, its link (none for a widened or APPLYING revert), the
// message and the next steps.
type PendingRevert struct {
	ledger.Revert
	Headline      string
	RevertURL     string
	PersonMessage string
	Links         []mcp.Link
	NextSteps     []mcp.NextStep
}

// ListPending returns one page of the agent's open held writes and
// reverts, in one id order with one cursor (LP-1). It touches no link
// unless p.Reissue is set: then each PENDING item gets a new short link and
// its earlier one stops working, a widened revert first reset to the
// agent's proposal (CONTRACT.md, Link secrets).
func (s *Service) ListPending(ctx context.Context, p PendingParams) (pagination.Page[PendingEntry], error) {
	if _, err := s.findRun(ctx, p.RunID); err != nil {
		return pagination.Page[PendingEntry]{}, err
	}
	sort, err := p.ParseSort(ledger.ApprovalSortSpec)
	if err != nil {
		return pagination.Page[PendingEntry]{}, fmt.Errorf("%w: %w", ledger.ErrInvalidParams, err)
	}
	var entries []PendingEntry
	more := false
	if p.Kind != KindRevert && p.Status != ledger.RevertApplying {
		page, err := s.Approvals.ListApprovals(ctx, ledger.ApprovalListParams{Params: p.Params, RunID: p.RunID, Status: p.Status})
		if err != nil {
			return pagination.Page[PendingEntry]{}, err
		}
		for i := range page.Items {
			entries = append(entries, PendingEntry{Approval: &PendingItem{Approval: page.Items[i]}})
		}
		more = page.NextCursor != ""
	}
	if p.Kind != KindApproval && p.Status != ledger.ApprovalApproved && p.RunID == uuid.Nil {
		page, err := s.Reverts.ListOpenReverts(ctx, ledger.RevertListParams{Params: p.Params, Status: p.Status})
		if err != nil {
			return pagination.Page[PendingEntry]{}, err
		}
		for i := range page.Items {
			entries = append(entries, PendingEntry{Revert: &PendingRevert{Revert: page.Items[i]}})
		}
		more = more || page.NextCursor != ""
	}
	slices.SortFunc(entries, func(a, b PendingEntry) int {
		if sort.Desc {
			return strings.Compare(b.id().String(), a.id().String())
		}
		return strings.Compare(a.id().String(), b.id().String())
	})
	out := pagination.Page[PendingEntry]{Items: entries}
	if len(entries) > p.Limit || more {
		out.Items = entries[:p.Limit]
		out.NextCursor = pagination.EncodeIDCursor(out.Items[p.Limit-1].id().String())
	}
	for _, e := range out.Items {
		if err := s.pendingGuidance(ctx, e, p.Reissue); err != nil {
			return pagination.Page[PendingEntry]{}, err
		}
	}
	return out, nil
}

// pendingGuidance fills e with its link, message and next steps.
func (s *Service) pendingGuidance(ctx context.Context, e PendingEntry, reissue bool) error {
	if a := e.Approval; a != nil {
		n, err := s.approvalNotice(ctx, a.ID, a.BindingText, a.Lines, a.ExpiresAt, reissue)
		if err != nil {
			return err
		}
		a.Notice = n.ApprovalNotice
		a.PersonMessage, a.Links, a.NextSteps, err = s.itemGuidance(*a)
		return err
	}
	return s.pendingRevert(ctx, e.Revert, reissue)
}

// pendingRevert fills an open revert's headline, link, message and steps
// (CONTRACT.md, Reverts in list_pending): an APPLYING plan goes to the
// agent's batch loop; a PENDING revert goes to the person, at a new short
// link on reissue, at its long link otherwise, and on the page they
// widened on for a widened revert.
func (s *Service) pendingRevert(ctx context.Context, p *PendingRevert, reissue bool) error {
	if p.Status == ledger.RevertApplying {
		headline, err := revertHeadline(p.Revert)
		if err != nil {
			return err
		}
		p.Headline = headline
		p.PersonMessage = fmt.Sprintf("%s You signed it; the agent restores it in batches by %s.", headline, applyByText(p.Revert))
		p.NextSteps = applyingSteps(p.ID)
		return nil
	}
	if reissue {
		r, err := s.prepareReissue(ctx, p.Revert)
		if err != nil {
			return err
		}
		n, err := s.revertNotice(ctx, r)
		if err != nil {
			return err
		}
		s.notifyRevert(ctx, r, n)
		p.Revert, p.Headline, p.RevertURL, p.PersonMessage, p.Links = r, n.Headline, n.URL, n.Message, n.Links
		p.NextSteps = pendingRevertSteps(r.ID, n.URL, "Open the new link, review the rows and sign with your passkey.")
		return nil
	}
	headline, err := revertHeadline(p.Revert)
	if err != nil {
		return err
	}
	p.Headline = headline
	expires := p.ExpiresAt.UTC().Format(personTime)
	if p.Widened {
		p.PersonMessage = fmt.Sprintf("%s %s It waits for your passkey on the page where you changed the scope, until %s.",
			widenedMessage, headline, expires)
		p.NextSteps = pendingRevertSteps(p.ID, "", "Sign with your passkey on the page where you changed the scope.")
		return nil
	}
	if p.RevertURL, err = s.longRevertLink(ctx, p.Revert); err != nil {
		return err
	}
	p.PersonMessage = fmt.Sprintf("%s It waits for your passkey at the link the agent gave you, until %s. If you lost it, "+
		"ask the agent for a new one.", headline, expires)
	p.NextSteps = pendingRevertSteps(p.ID, p.RevertURL, "Open the revert link the agent gave you, review the rows and sign with your passkey.")
	return nil
}

// pendingRevertSteps: the person signs (at link, or "" for the page they
// widened on), then the agent reads the result once.
func pendingRevertSteps(id uuid.UUID, link, open string) []mcp.NextStep {
	return []mcp.NextStep{
		openLink(link, open),
		callTool(toolRequestRevert, map[string]any{argRevertID: id.String(), argWaitForSignature: 0},
			"When the person says they signed, call this once; it returns at once."),
	}
}
