package agent

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ScopeProof is the person's widen proof: a passkey assertion over
// revert.RescopeChallenge, its fields base64url.
type ScopeProof struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

func (p ScopeProof) assertion() passkey.Assertion {
	return passkey.Assertion{
		CredentialID: p.CredentialID, AuthenticatorData: p.AuthenticatorData,
		ClientDataJSON: p.ClientDataJSON, Signature: p.Signature,
	}
}

// The pages' reveal routes (CONTRACT.md, Approvals, Rows hidden from the
// agent; Local pages, POST …/reveal): the person proves with their passkey
// that they want to see the values of the lines the agent role cannot
// read, and Postgres returns them for this one answer. The engine keeps
// nothing: the reveal key, the ticket and the rows live for one request,
// are never logged, and never reach the MCP channel.

// RevealRequest is the body of POST …/reveal (reveal-request.schema.json):
// the person's proof and the reveal secret the page made for it.
type RevealRequest struct {
	Proof        ScopeProof `json:"proof"`
	RevealSecret string     `json:"revealSecret"`
}

// revealKey is the key Postgres checks the proof against, derived from the
// page's reveal secret, which never reaches Postgres.
func (in RevealRequest) revealKey() ([]byte, error) {
	raw, err := links.DecodeSecret(in.RevealSecret)
	if err != nil {
		return nil, &ArgumentError{Message: "revealSecret must be 16 random bytes, base64url without padding"}
	}
	defer clear(raw)
	return approval.RevealKey(raw)
}

// checkedAnswer is the answer the page gets, checked first as the page
// checks it: rows of redacted lines, in order, each hashing to its line
// (or with its SECRET columns null). A row that fails is a defect, never
// shown.
func checkedAnswer(lines []string, rows []approval.RevealedRow) (approval.RevealAnswer, error) {
	if rows == nil {
		rows = []approval.RevealedRow{}
	}
	answer := approval.RevealAnswer{Rows: rows}
	if _, err := approval.CheckRevealAnswer(lines, answer); err != nil {
		return approval.RevealAnswer{}, fmt.Errorf("the guard's reveal answer does not match the request: %w", err)
	}
	return answer, nil
}

// revealRefused is every refused proof, key, nonce or ticket: one answer,
// so the agent holding the link learns nothing from which check failed. Its
// step opens the page again (link, with the page's own secret: the answer
// goes back to that page only) to press Show values with passkey once more.
func revealRefused(code, link string) error {
	te := &toolresult.ToolError{
		Code: code, Reason: guardmodel.RevealRefused,
		Message:       "showing the hidden rows was refused: it needs the person's passkey on this page; nothing was shown",
		PersonMessage: "Your passkey didn't confirm. Nothing was shown; try again.",
	}
	steps, err := guidance.NewSteps().OpenLink(link, "Open this page again and press Show values with passkey once more.").Build()
	if err != nil {
		return err
	}
	te.NextSteps = steps
	return &PageError{ToolError: te}
}

// pageLink is the page's own short link, with the secret it holds.
func (s *Service) pageLink(page func(string, uuid.UUID) string, id uuid.UUID, secret string) string {
	return links.WithSecret(page(s.deps.Core.PagesBase, id), secret)
}

// revealRowsChanged is a reveal whose hidden rows changed since the agent
// asked: nothing is shown, and the item can no longer apply as signed.
func revealRowsChanged(code, what, then string) error {
	return &PageError{ToolError: &toolresult.ToolError{
		Code: code, Reason: guidance.ReasonRowsChanged,
		Message:       fmt.Sprintf("the hidden rows of this %s changed since it was prepared; nothing was shown", what),
		PersonMessage: "These rows changed since the agent asked. " + then + ".",
	}}
}
