package app

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// RevertRequest is the revert request of a revert this agent's role
// prepared that the person has not signed yet, for the page holding
// secret, its live link secret, with the nonce of the next widen read from
// the store. A revert not widened is served from the store. A widened one is
// served from the engine's memory, since the agent role's view shows no
// binding or lines (RS-5): an engine that restarted since asks the person
// to widen again (owner, Q13), with the nonce that widen signs.
func (s *Service) RevertRequest(ctx context.Context, id uuid.UUID, secret string) (revert.Request, error) {
	return s.revert.RevertRequest(ctx, id, secret)
}

// RelayRevert applies the person's signed revert (apply_revert): the store
// verifies the signature and runs the revert, or for a large plan records
// it for the agent's batches.
// RelayRevert is the revert use case's RelayRevert.
func (s *Service) RelayRevert(ctx context.Context, r revert.Response) (action.AppliedRevert, linksvc.Receipt, error) {
	return s.revert.RelayRevert(ctx, r)
}

// RejectRevert rejects a revert this agent's role prepared, for the person
// on the revert page that holds secret, the revert's live link secret (the
// pages checked it). For a widened revert the engine adds the scope token
// it holds for this link; the store refuses the reject without it. On
// success the link is revoked: inside a Vault session once the answer went
// out, since revoking it ends the session.
// RejectRevert is the revert use case's RejectRevert.
func (s *Service) RejectRevert(ctx context.Context, id uuid.UUID, secret string, in revertsvc.RejectRequest) (revertsvc.RejectResponse, error) {
	return s.revert.RejectRevert(ctx, id, secret, in)
}

// RescopeRevert changes the scope of a revert this agent's role prepared,
// for the person on the revert page that holds secret, the revert's live
// link secret (the pages checked it). Without a proof it is a narrow: the
// engine adds the scope token it holds for this link, if any. With a proof
// and the page's new secret it is a widen: on success the revert's link is
// rotated to that secret, and the token, lines and catalog the store
// returned are kept in memory for it.
// RescopeRevert is the revert use case's RescopeRevert.
func (s *Service) RescopeRevert(ctx context.Context, id uuid.UUID, secret string, in revertsvc.ScopeRequest) (revertsvc.ScopeResponse, error) {
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
// secret. It serializes with the revert's other page routes; the store
// locks the revert row, so a signature racing it comes first or second,
// never between.
// RevealRevert is the revert use case's RevealRevert.
func (s *Service) RevealRevert(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	return s.revert.RevealRevert(ctx, id, secret, in)
}
