package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// deliverReissued makes the notices of a list_pending page that issued new
// links: one per item it issued a link for, each with the link of that
// item in the answer.
func (ac *approvalCase) deliverReissued(items []PendingEntry) {
	for _, e := range items {
		switch {
		case e.Approval != nil && e.Approval.issued:
			d := pendingFromDomain(*e.Approval)
			ac.delivery.deliver(LinkNotice{
				Kind: NoticeLinkReplaced, ApprovalID: e.Approval.ID, Headline: d.Headline, ExpiresAt: e.Approval.ExpiresAt, Link: d.ApprovalURL,
			})
		case e.Revert != nil && e.Revert.issued:
			d := pendingRevertFromDomain(*e.Revert)
			ac.delivery.deliver(LinkNotice{
				Kind: NoticeLinkReplaced, RevertID: e.Revert.ID, Headline: d.Headline, ExpiresAt: e.Revert.ExpiresAt, Link: d.RevertURL,
			})
		}
	}
}

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

// ListPending returns one page of the agent's open held writes and
// reverts, in one id order with one cursor (LP-1). It touches no link
// unless p.Reissue is set: then each PENDING item gets a new short link and
// its earlier one stops working, a widened revert first reset to the
// agent's proposal (CONTRACT.md, Link secrets).
func (ac *approvalCase) ListPending(ctx context.Context, p PendingParams) (pagination.Page[PendingEntry], error) {
	if _, err := findRun(ctx, ac.core.Store, p.RunID); err != nil {
		return pagination.Page[PendingEntry]{}, err
	}
	sort, err := p.ParseSort(ac.deps.SortSpec)
	if err != nil {
		return pagination.Page[PendingEntry]{}, fmt.Errorf("%w: %w", ac.core.Errors.InvalidParams, err)
	}
	var entries []PendingEntry
	more := false
	if p.Kind != guidance.KindRevert && p.Status != action.RevertApplying {
		page, err := ac.deps.Store.ListApprovals(ctx, action.ApprovalListParams{Params: p.Params, RunID: p.RunID, Status: p.Status})
		if err != nil {
			return pagination.Page[PendingEntry]{}, err
		}
		for i := range page.Items {
			entries = append(entries, PendingEntry{Approval: &PendingItem{Approval: page.Items[i]}})
		}
		more = page.NextCursor != ""
	}
	if p.Kind != guidance.KindApproval && p.Status != action.ApprovalApproved && p.RunID == uuid.Nil {
		page, err := ac.reverts.ListOpenReverts(ctx, action.RevertListParams{Params: p.Params, Status: p.Status})
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
		if err := ac.pendingGuidance(ctx, e, p.Reissue); err != nil {
			return pagination.Page[PendingEntry]{}, err
		}
	}
	// Only once the whole page is built: an item's failure fails the call,
	// and then no notice leaves for a link the agent never got.
	ac.deliverReissued(out.Items)
	return out, nil
}

// pendingGuidance fills e with its link, message and next steps.
func (ac *approvalCase) pendingGuidance(ctx context.Context, e PendingEntry, reissue bool) error {
	if a := e.Approval; a != nil {
		n, err := ac.approvalNotice(ctx, a.ID, a.RunID, requestOf(a.Approval), a.ExpiresAt, reissue)
		if err != nil {
			return err
		}
		a.Notice = n.ApprovalNotice
		a.Restated = !reissue && (ac.delivery.shortLinked(a.ID) || isPageAddress(n.ApprovalURL))
		if n.reason == reasonRequestTooLarge {
			a.tooLargeSteps = n.steps
		}
		if !ac.waitsForPerson(*a) {
			a.Notice.RequestFile = nil // nothing left to sign: no request to send
		}
		a.issued = reissue && n.shortURL != "" && ac.waitsForPerson(*a)
		a.PersonMessage, a.Links, a.NextSteps, err = ac.itemGuidance(*a)
		return err
	}
	return ac.reverts.pendingRevert(ctx, e.Revert, reissue)
}
