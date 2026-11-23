package agent

import (
	"context"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// revertCase is the revert use case: previewing, planning, requesting, applying,
// rescoping, rejecting and revealing a revert. It holds a reference to the
// shared core group and to its own RevertDeps, and owns the reverts the person
// rescoped through this engine. What it needs from the other use cases it names
// as small ports of its own.
type revertCase struct {
	core     *CoreDeps
	deps     *RevertDeps
	delivery revertDelivery
	describe revertDescribe
	admit    admitter
	// rescopes are the reverts the person rescoped through this engine, in
	// memory only (CONTRACT.md, Rescope, widen and reject).
	rescopes *rescopes
}

// revertDelivery is what the revert use case asks of the delivery use case.
type revertDelivery interface {
	AwaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error
	CarriesLarge(cost int64) bool
	ColumnsOf(ctx context.Context, lines []string) approval.ColumnOrder
	CredentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	Deliver(n linksvc.LinkNotice)
	LargeShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, cost int64) (string, error)
	PageAddress(page func(string, uuid.UUID) string, id uuid.UUID) string
	PageLink(page func(string, uuid.UUID) string, id uuid.UUID, secret string) string
	RevertTooLargeError(id uuid.UUID, cost int64, expires time.Time) error
	ShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error)
	ShortLinked(id uuid.UUID) bool
	SignReceipt(p channel.Receipt, verb, noun string) (linksvc.Receipt, error)
	TooLargeMessage(what string, cost int64, expires time.Time, isRevert bool) string
	LinkRevoke(id uuid.UUID) error
	LinkRotate(id uuid.UUID, secret string, expires time.Time) (links.Rotated, error)
	LinkExtend(id uuid.UUID, expires time.Time) (links.RelayLink, bool, error)
	LinkReset(id uuid.UUID, until time.Time) error
	LinkWasReset(id uuid.UUID, secret string) bool
	RelayRegister(ctx context.Context, token channel.LinkToken, expires time.Time) error
	NotifyRevertTo(ctx context.Context, n linksvc.RevertNotice) error
}

// revertDescribe is what the revert use case reads of the describe use case.
type revertDescribe interface {
	statementTimeout() time.Duration
}

func newRevertCase(core *CoreDeps, deps *RevertDeps, delivery revertDelivery, describe revertDescribe, admit admitter) *revertCase {
	return &revertCase{core: core, deps: deps, delivery: delivery, describe: describe, admit: admit, rescopes: newRescopes()}
}

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet, for the page holding
// secret, its live link secret, with the nonce of the next widen read from
// Postgres. A revert not widened is served from Postgres. A widened one is
// served from the engine's memory, since the agent role's view shows no
// binding or lines (RS-5): an engine that restarted since asks the person
// to widen again (owner, Q13), with the nonce that widen signs.
// RevertRequest is the revert use case's RevertRequest.
func (s *Service) RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error) {
	return s.revert.RevertRequest(ctx, id, secret)
}

// RelayRevert applies the person's signed revert (apply_revert): Postgres
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
// RelayRevert is the revert use case's RelayRevert.
func (s *Service) RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, linksvc.Receipt, error) {
	return s.revert.RelayRevert(ctx, r)
}

// RejectRevert rejects a revert this agent's role prepared, for the person
// on the revert page that holds secret, the revert's live link secret (the
// pages checked it). For a widened revert the engine adds the scope token
// it holds for this link; Postgres refuses the reject without it. On
// success the link is revoked: inside a Vault session once the answer went
// out, since revoking it ends the session.
// RejectRevert is the revert use case's RejectRevert.
func (s *Service) RejectRevert(ctx context.Context, id uuid.UUID, secret string, in RejectRequest) (RejectResponse, error) {
	return s.revert.RejectRevert(ctx, id, secret, in)
}

// RescopeRevert changes the scope of a revert this agent's role prepared,
// for the person on the revert page that holds secret, the revert's live
// link secret (the pages checked it). Without a proof it is a narrow: the
// engine adds the scope token it holds for this link, if any. With a proof
// and the page's new secret it is a widen: on success the revert's link is
// rotated to that secret, and the token, lines and catalog Postgres
// returned are kept in memory for it.
// RescopeRevert is the revert use case's RescopeRevert.
func (s *Service) RescopeRevert(ctx context.Context, id uuid.UUID, secret string, in ScopeRequest) (ScopeResponse, error) {
	return s.revert.RescopeRevert(ctx, id, secret, in)
}

// CheckResetLink reports whether secret is a link of revert id that the
// agent's reset revoked (NOT_FOUND reason LINK_RESET on the pages).
// CheckResetLink is the revert use case's CheckResetLink.
func (s *Service) CheckResetLink(id uuid.UUID, secret string) bool {
	return s.revert.CheckResetLink(id, secret)
}

// RevealRevert reveals the hidden rows of a revert this agent's role
// prepared to the person on the revert page holding secret, its live link
// secret. It serializes with the revert's other page routes; Postgres
// locks the revert row, so a signature racing it comes first or second,
// never between.
// RevealRevert is the revert use case's RevealRevert.
func (s *Service) RevealRevert(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return s.revert.RevealRevert(ctx, id, secret, in)
}

// PreviewRevert returns what reverting the scope would restore and skip.
// It changes nothing: the guard runs the revert on trial and undoes it.
// The scope must be the agent's own (RS-1): another agent's id answers
// NOT_FOUND before any guard call.
// PreviewRevert is the revert use case's PreviewRevert.
func (s *Service) PreviewRevert(ctx context.Context, p PreviewRevertParams) (RevertPreview, error) {
	return s.revert.PreviewRevert(ctx, p)
}

// RevertPlan returns a large revert plan this agent prepared, its progress
// and one page of its lines, for the agent to apply with ApplyRevertBatch
// once the person signed it.
// RevertPlan is the revert use case's RevertPlan.
func (s *Service) RevertPlan(ctx context.Context, p action.RevertLineParams) (RevertPlan, error) {
	return s.revert.RevertPlan(ctx, p)
}

// ApplyRevertBatch applies lines of a signed plan this agent prepared.
// Postgres checks them against the signed plan and re-checks each row.
// ApplyRevertBatch is the revert use case's ApplyRevertBatch.
func (s *Service) ApplyRevertBatch(ctx context.Context, p ApplyRevertBatchParams) (AppliedBatch, error) {
	return s.revert.ApplyRevertBatch(ctx, p)
}

// RequestRevert is the revert use case's RequestRevert.
func (s *Service) RequestRevert(ctx context.Context, p RequestRevertParams) (RequestedRevert, error) {
	return s.revert.RequestRevert(ctx, p)
}

// AwaitRevert returns the state of a revert this agent requested. With
// Reissue on a PENDING revert it issues a new link and returns at once;
// otherwise it reads the revert about every s.deps.Delivery.Poll until it is not PENDING
// or Wait is over. It never signs: the person signs on the revert page.
// AwaitRevert is the revert use case's AwaitRevert.
func (s *Service) AwaitRevert(ctx context.Context, p AwaitRevertParams) (RequestedRevert, error) {
	return s.revert.AwaitRevert(ctx, p)
}

// ListOpenReverts lists the role's PENDING and APPLYING reverts, for the
// approval use case's pending list.
func (rc *revertCase) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return rc.deps.Store.ListOpenReverts(ctx, p)
}
