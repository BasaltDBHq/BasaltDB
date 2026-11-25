// Package revertpage serves the revert page's API (CONTRACT.md, Local
// pages): the request, the signed revert, the scope, the reject and the
// reveal, on the page server's agents. app mounts its handlers on the page
// server.
package revertpage

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
)

// revertPage serves the revert page's API on the server's agents.
type revertPage struct{ s *pageserver.Server }

// NewRevertHandlers are the revert routes' handlers on s's agents, for
// s.MountReverts.
func NewRevertHandlers(s *pageserver.Server) pageserver.RevertHandlers {
	p := revertPage{s: s}
	return pageserver.RevertHandlers{Get: p.getRevert, Apply: p.postRevert, Scope: p.postScope, Reject: p.postReject, Reveal: p.postRevertReveal}
}

// appliedDTO is the relay's answer for a revert: the applied revert, with
// the engine's receipt or why there is none.
type appliedDTO struct {
	action.AppliedRevert
	Receipt   string `json:"receipt,omitempty"`
	NoReceipt string `json:"noReceipt,omitempty"`
}

// relayedRevert is what RelayRevert returns, for Find.
type relayedRevert struct {
	applied action.AppliedRevert
	receipt linksvc.Receipt
}

func (p revertPage) getRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.RevertParam)
	if !ok {
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	req, err := pageserver.Find(r.Context(), p.s, func(ctx context.Context, a pageserver.Agent) (revert.Request, error) {
		return a.RevertRequest(ctx, id, secret)
	})
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, req)
}

func (p revertPage) postRevert(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.RevertParam)
	if !ok {
		return
	}
	body, ok := p.s.Body(w, r)
	if !ok {
		return
	}
	resp, err := revert.DecodeResponse(body)
	if err != nil || resp.RevertID != id {
		p.s.Fail(w, &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: "the body is not this revert's signed response"})
		return
	}
	out, err := pageserver.Find(r.Context(), p.s, func(ctx context.Context, a pageserver.Agent) (relayedRevert, error) {
		applied, receipt, err := a.RelayRevert(ctx, resp)
		return relayedRevert{applied: applied, receipt: receipt}, err
	})
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, appliedDTO{AppliedRevert: out.applied, Receipt: out.receipt.Token, NoReceipt: out.receipt.Missing})
}

// postScope narrows or widens a revert's scope for the page (CONTRACT.md,
// Local pages, POST …/scope). The body is decoded strictly: an unknown key
// (the reserved store included) or a proof without its new secret is
// refused on its shape, before anything is looked up. The store checks the
// rest in the contract's order.
func (p revertPage) postScope(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.RevertParam)
	if !ok {
		return
	}
	body, ok := p.s.Body(w, r)
	if !ok {
		return
	}
	var in revertsvc.ScopeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() || (in.Proof == nil) != (in.NewSecret == "") {
		p.s.Fail(w, &toolresult.ToolError{
			Code:    guidance.CodeInvalidArgument,
			Message: "the body must be {\"select\", \"proof\"?, \"newSecret\"?} (revert-scope-request.schema.json), proof and newSecret together",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := pageserver.Find(r.Context(), p.s, func(ctx context.Context, a pageserver.Agent) (revertsvc.ScopeResponse, error) {
		return a.RescopeRevert(ctx, id, secret, in)
	})
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, out)
}

// postReject rejects a revert for the page (CONTRACT.md, Local pages, POST
// …/reject). The body is decoded strictly, { "note"? }; the note's length is
// the service's to check. The store decides the rest.
func (p revertPage) postReject(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.RevertParam)
	if !ok {
		return
	}
	body, ok := p.s.Body(w, r)
	if !ok {
		return
	}
	var in revertsvc.RejectRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() {
		p.s.Fail(w, &toolresult.ToolError{
			Code:    guidance.CodeInvalidArgument,
			Message: "the body must be {\"note\"?} (revert-reject-request.schema.json)",
		})
		return
	}
	secret := r.Header.Get(links.SecretHeader)
	out, err := pageserver.Find(r.Context(), p.s, func(ctx context.Context, a pageserver.Agent) (revertsvc.RejectResponse, error) {
		return a.RejectRevert(ctx, id, secret, in)
	})
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, out)
}

// postRevertReveal shows the person the values of the revert's redacted
// lines (Server.Reveal).
func (p revertPage) postRevertReveal(w http.ResponseWriter, r *http.Request) {
	p.s.Reveal(w, r, pageserver.RevertParam, func(ctx context.Context, a pageserver.Agent, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
		return a.RevealRevert(ctx, id, secret, in)
	})
}
