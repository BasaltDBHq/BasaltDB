package agent

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// The revert page's reject route (CONTRACT.md, Revert, Rescope, widen and
// reject; Local pages, POST /api/v1/reverts/{revertId}/reject): the person
// rejects the agent's revert, with an optional note for the agent. No
// passkey: rejecting can only stop a revert. Postgres marks it REJECTED and
// records REVERT_REJECTED; the engine then revokes the revert's link.

// RejectRequest is the body of POST …/reject
// (revert-reject-request.schema.json).
type RejectRequest struct {
	Note *string `json:"note,omitempty"`
}

// RejectResponse is the 200 answer of POST …/reject.
type RejectResponse struct {
	RevertID   string `json:"revertId"`
	Status     string `json:"status"`
	RejectedAt string `json:"rejectedAt"`
}

// RejectRevert rejects a revert this agent's role prepared, for the person
// on the revert page that holds secret, the revert's live link secret (the
// pages checked it). For a widened revert the engine adds the scope token
// it holds for this link; Postgres refuses the reject without it. On
// success the link is revoked: inside a Vault session once the answer went
// out, since revoking it ends the session.
func (s *Service) RejectRevert(ctx context.Context, id uuid.UUID, secret string, in RejectRequest) (RejectResponse, error) {
	note, err := rejectNote(in.Note)
	if err != nil {
		return RejectResponse{}, err
	}
	release, err := s.rescopes.lock(ctx, id)
	if err != nil {
		return RejectResponse{}, err
	}
	defer release()
	r, err := s.openRevert(ctx, id, nil)
	if err != nil {
		return RejectResponse{}, err
	}
	st, _, err := s.heldState(r, secret)
	if err != nil {
		return RejectResponse{}, err
	}
	out, err := s.Reverts.RejectRevert(ctx, id, note, st.token)
	if err != nil {
		return RejectResponse{}, s.rejectError(r, st.token != nil, err)
	}
	s.rescopes.drop(id)
	s.revokeRejected(ctx, id)
	return RejectResponse{RevertID: out.RevertID.String(), Status: out.Status, RejectedAt: timeText(out.RejectedAt)}, nil
}

// rejectNote is the person's note as Postgres takes it ("" for none): 1 to
// guard.MaxRejectNote characters of text. The agent reads it and may show
// it to the person, so no control character other than a newline or a tab,
// and no bidirectional control that could make it read otherwise.
func rejectNote(note *string) (string, error) {
	if note == nil {
		return "", nil
	}
	n := utf8.RuneCountInString(*note)
	if n == 0 || n > guard.MaxRejectNote || strings.IndexFunc(*note, refusedInNote) >= 0 {
		return "", &ArgumentError{Message: "note must be 1 to 500 characters of text, with no control characters other than newlines and tabs"}
	}
	return *note, nil
}

// refusedInNote reports a rune a reject note may not hold: a control
// character (C0, DEL, C1) other than a newline or a tab, or a bidirectional
// mark, embedding, override or isolate.
func refusedInNote(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case unicode.IsControl(r):
		return true
	case r == '\u061c' || r == '\u200e' || r == '\u200f':
		return true
	case r >= '\u202a' && r <= '\u202e':
		return true
	}
	return r >= '\u2066' && r <= '\u2069'
}

// revokeRejected revokes a rejected revert's link. A failure leaves a link
// to a revert Postgres refuses everything for: it is logged.
func (s *Service) revokeRejected(ctx context.Context, id uuid.UUID) {
	revoke := func() {
		if err := s.Links.RevokeItem(id); err != nil {
			s.Log.Warn("revoke a rejected revert's link", "id", id, "err", err)
		}
	}
	if vault.AfterAnswer(ctx, revoke) {
		return
	}
	revoke()
}

// rejectError is the page's answer to a reject Postgres refused. A refused
// token the engine held means the person's scope is gone (the agent role
// reset the revert directly): LINK_RESET, as heldState answers. A refused
// reject without a token is one fixed answer. A revert Postgres no longer
// finds for the role reads as an unknown id, an expiry is REVERT_EXPIRED,
// and a revert signed or rejected meanwhile is REVERT_INVALID.
func (s *Service) rejectError(r ledger.Revert, heldToken bool, err error) error {
	code, _ := guard.CodeOf(err)
	var pe *pgconn.PgError
	detail := ""
	if errors.As(err, &pe) {
		detail = pe.Detail
	}
	switch {
	case code == guard.CodeRevertInvalid && detail == guard.RevertWidenRefused && heldToken:
		return s.personScopeGone(r)
	case code == guard.CodeRevertInvalid && detail == guard.RevertWidenRefused:
		return rejectRefused()
	case code == guard.CodeRevertInvalid && detail == revertNotFoundDetail:
		return ErrNotThisAgent
	case code == guard.CodeRevertExpired:
		return s.revertExpired(r)
	case code == guard.CodeRevertInvalid:
		return &PageError{ToolError: &mcp.ToolError{Code: CodeRevertInvalid,
			Message:       "the revert can no longer be rejected: it was signed or rejected meanwhile",
			PersonMessage: "This revert can no longer be rejected: it was signed or rejected meanwhile."}}
	}
	return err
}

// revertNotFoundDetail is the guard's detail for a revert the calling role
// did not prepare, or none (_revert_lock_pending).
const revertNotFoundDetail = "no such revert"

// rejectRefused is a reject Postgres refused for its scope token: after a
// widen only the page holding the rotated link can reject, and only while
// the engine holds the token (it lives in memory).
func rejectRefused() error {
	return &PageError{ToolError: &mcp.ToolError{Code: CodeRevertInvalid,
		Message: "the reject was refused: after the person widened this revert, only the page that widened it can reject it; nothing changed",
		PersonMessage: "This reject was refused, and nothing changed. The engine no longer holds the scope you chose (it restarted): " +
			"include other agents' changes again on this page to reject it, or close the page. Nothing is reverted unless " +
			"you sign, and the revert expires within the hour."}}
}
