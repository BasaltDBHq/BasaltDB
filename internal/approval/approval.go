// Package approval encodes and checks the approval codes that travel between
// the engine, the static approval page and whoever relays the signed result
// (CONTRACT.md, Approvals): the binding text Postgres builds, the preview
// lines it covers, the request in the approval link, and the response code
// the page outputs. Nothing here decides whether an approval counts; Postgres
// does, in basalt_meta.submit_approval and the guard's commit check.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// Code prefixes (CONTRACT.md, Approvals, Codes).
const (
	// RequestPrefix starts the approval link's fragment.
	RequestPrefix = "1."
	// ResponsePrefix starts the code the approval page outputs.
	ResponsePrefix = "basalt-approval.1."
)

// KindApprove is the binding kind of an approval; M3 adds REVERT.
const KindApprove = "APPROVE"

// Limits from the default policy and for decoding untrusted codes.
const (
	// MaxRows is the most rows one held action can change (foundation,
	// Default policy: over 50 is refused).
	MaxRows = 50
	// maxRequestBytes caps the inflated request, so a crafted link cannot
	// inflate without bound.
	maxRequestBytes = 1 << 20
	// maxFragmentLen caps the compressed fragment before decoding.
	maxFragmentLen = 1 << 20
)

// ErrInvalid wraps every reason a code or binding is refused.
var ErrInvalid = errors.New("approval code invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Binding is the parsed binding text. The text itself, not this struct, is
// what the passkey signs: never re-serialize it.
type Binding struct {
	Kind            string            `json:"kind"`
	ApprovalID      uuid.UUID         `json:"approvalId"`
	Database        string            `json:"database"`
	Agent           string            `json:"agent"`
	RunID           uuid.UUID         `json:"runId"`
	TaskID          *uuid.UUID        `json:"taskId"`
	Intent          string            `json:"intent"`
	Statement       string            `json:"statement"`
	Params          []json.RawMessage `json:"params"`
	AssignedColumns []string          `json:"assignedColumns"`
	Rows            int               `json:"rows"`
	RowsHash        string            `json:"rowsHash"`
	ExpiresAt       time.Time         `json:"expiresAt"`
}

// ParseBinding parses binding text for display and checks.
func ParseBinding(text string) (Binding, error) {
	var b Binding
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Binding{}, invalid("binding: %v", err)
	}
	if b.Kind != KindApprove {
		return Binding{}, invalid("binding kind %q", b.Kind)
	}
	if b.Rows < 1 || b.Rows > MaxRows {
		return Binding{}, invalid("binding rows %d out of 1..%d", b.Rows, MaxRows)
	}
	if _, err := hex.DecodeString(b.RowsHash); err != nil || len(b.RowsHash) != sha256.Size*2 {
		return Binding{}, invalid("binding rowsHash is not a sha256 hex digest")
	}
	return b, nil
}

// Challenge is the WebAuthn challenge for a binding: sha256 of its UTF-8
// bytes.
func Challenge(bindingText string) []byte {
	sum := sha256.Sum256([]byte(bindingText))
	return sum[:]
}

// RowsHash is the lowercase hex sha256 of the preview lines joined by "\n",
// the binding's rowsHash.
func RowsHash(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// Request is what the engine puts in the approval link.
type Request struct {
	ApprovalID    uuid.UUID       `json:"approvalId"`
	Binding       string          `json:"binding"`
	Lines         []string        `json:"lines"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
}

// Check parses the binding and checks the request against it: same approval,
// one line per row, and the lines hash to rowsHash. The approval page makes
// the same checks before asking for a signature.
func (r Request) Check() (Binding, error) {
	b, err := ParseBinding(r.Binding)
	if err != nil {
		return Binding{}, err
	}
	if b.ApprovalID != r.ApprovalID {
		return Binding{}, invalid("request is for approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	if len(r.Lines) != b.Rows {
		return Binding{}, invalid("request has %d lines, binding %d rows", len(r.Lines), b.Rows)
	}
	if RowsHash(r.Lines) != b.RowsHash {
		return Binding{}, invalid("preview lines do not match the binding's rowsHash")
	}
	return b, nil
}

// Fragment returns the link fragment (without '#'):
// 1.<base64url(deflate-raw(json))>.
func (r Request) Fragment() (string, error) {
	return EncodeFragment(r)
}

// URL returns the long approval link on the pages at base (links):
// <base>/approvals/<approvalId>#1.<request>.
func (r Request) URL(base string) (string, error) {
	frag, err := r.Fragment()
	if err != nil {
		return "", err
	}
	return links.Approval(base, r.ApprovalID) + "#" + frag, nil
}

// ParseRequest decodes an approval link fragment, with or without '#', and
// checks it (Check).
func ParseRequest(fragment string) (Request, Binding, error) {
	var r Request
	if err := DecodeFragment(fragment, "approval request", &r); err != nil {
		return Request{}, Binding{}, err
	}
	b, err := r.Check()
	if err != nil {
		return Request{}, Binding{}, err
	}
	return r, b, nil
}

// Response is what the approval page outputs after the person signs.
type Response struct {
	ApprovalID        uuid.UUID     `json:"approvalId"`
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

// NewResponse wraps an assertion for approvalID.
func NewResponse(approvalID uuid.UUID, a passkey.Assertion) Response {
	return Response{
		ApprovalID:        approvalID,
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}
}

// Assertion returns the WebAuthn assertion the response carries.
func (r Response) Assertion() passkey.Assertion {
	return passkey.Assertion{
		CredentialID:      r.CredentialID,
		AuthenticatorData: r.AuthenticatorData,
		ClientDataJSON:    r.ClientDataJSON,
		Signature:         r.Signature,
	}
}

// Code returns the text the person copies:
// basalt-approval.1.<base64url(json)>.
func (r Response) Code() (string, error) {
	return passkey.EncodeCode(ResponsePrefix, r)
}

// ParseResponse decodes a pasted response code. Surrounding whitespace is
// ignored.
func ParseResponse(code string) (Response, error) {
	var r Response
	if err := passkey.DecodeCode(ResponsePrefix, strings.TrimSpace(code), &r); err != nil {
		return Response{}, invalid("%v", err)
	}
	if len(r.CredentialID) == 0 || len(r.AuthenticatorData) == 0 || len(r.ClientDataJSON) == 0 || len(r.Signature) == 0 {
		return Response{}, invalid("approval response is missing a field")
	}
	return r, nil
}

// Verify checks a response against the binding text it should sign and the
// stored passkey, the way basalt_meta.submit_approval does (without the
// approval's state and expiry, which only Postgres knows). It returns the
// new signature counter.
func Verify(bindingText string, cred passkey.Credential, r Response) (uint32, error) {
	b, err := ParseBinding(bindingText)
	if err != nil {
		return 0, err
	}
	if b.ApprovalID != r.ApprovalID {
		return 0, invalid("response is for approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	count, err := passkey.VerifyAssertion(cred, Challenge(bindingText), r.Assertion())
	if err != nil {
		return 0, fmt.Errorf("approval %s: %w", r.ApprovalID, err)
	}
	return count, nil
}
