package approvaltest

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// fromCompact is the request a format 2 link carries, its id read from the
// binding; Check refuses a binding that does not parse.
func fromCompact(binding string, lines []string, ids []passkey.Bytes) approval.Request {
	r := approval.Request{Binding: binding, Lines: lines, CredentialIDs: ids}
	if b, err := approval.ParseBinding(binding); err == nil {
		r.ApprovalID = b.ApprovalID
	}
	return r
}

// ParseRequest decodes an approval link fragment of either format, with or
// without '#', and checks it (Check).
func ParseRequest(fragment string) (approval.Request, approval.Binding, error) {
	r, err := linkcodec.DecodeRequest(fragment, approval.MaxRows, fromCompact)
	if err != nil {
		return approval.Request{}, approval.Binding{}, approval.Invalid("approval request %v", err)
	}
	if r.RevealNonce != nil {
		return approval.Request{}, approval.Binding{}, approval.Invalid("a link carries no revealNonce: only the engine serves it")
	}
	if r.Columns != nil {
		return approval.Request{}, approval.Binding{}, approval.Invalid("a link carries no columns: only the engine serves them")
	}
	b, err := r.Check()
	if err != nil {
		return approval.Request{}, approval.Binding{}, err
	}
	return r, b, nil
}

// NewResponse wraps an assertion for approvalID.
func NewResponse(approvalID uuid.UUID, a passkey.Assertion) approval.Response {
	return approval.Response{
		ApprovalID:        approvalID,
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}
}

// Verify checks a response against the binding text it should sign and the
// stored passkey, the way basalt_meta.submit_approval does (without the
// approval's state and expiry, which only Postgres knows). It returns the
// new signature counter.
func Verify(bindingText string, cred passkey.Credential, r approval.Response) (uint32, error) {
	b, err := approval.ParseBinding(bindingText)
	if err != nil {
		return 0, err
	}
	if b.ApprovalID != r.ApprovalID {
		return 0, approval.Invalid("response is for approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	count, err := passkey.VerifyAssertion(cred, approval.Challenge(bindingText), r.Assertion())
	if err != nil {
		return 0, fmt.Errorf("approval %s: %w", r.ApprovalID, err)
	}
	return count, nil
}
