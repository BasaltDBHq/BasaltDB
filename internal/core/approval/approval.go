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

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Code prefixes (CONTRACT.md, Approvals, Codes).
const (
	// RequestPrefix starts the approval link's fragment: format 2, the
	// compact request. The pages also read format 1 (linkcodec).
	RequestPrefix = linkcodec.Format2
)

// KindApprove is the binding kind of an approval; M3 adds REVERT.
const KindApprove = "APPROVE"

// Limits from the default policy and for decoding untrusted codes.
const (
	// MaxRows is the most rows one held action can change; the default
	// policy refuses more than 50.
	MaxRows = 50
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

// Request is the approval request: what the engine's local pages serve, and
// what a format 1 link carries.
type Request struct {
	ApprovalID uuid.UUID `json:"approvalId"`
	Binding    string    `json:"binding"`
	Lines      []string  `json:"lines"`
	// RevealNonce is the nonce a reveal proof signs (Rows hidden from the
	// agent), served only by the engine, never carried in a long link.
	RevealNonce   passkey.Bytes   `json:"revealNonce,omitempty"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
	// Columns orders each table's columns as the table does (attnum), for
	// the page's display only (CONTRACT.md, Local pages): served only by
	// the engine, never signed, never carried in a link.
	Columns ColumnOrder `json:"columns,omitempty"`
}

// ColumnOrder maps a table, as the lines spell it, to its column names in
// table order. A present but null value decodes to an empty, non-nil map,
// so a link that names the field at all is told apart from one without it.
type ColumnOrder map[string][]string

// UnmarshalJSON decodes the map; null is an empty map, not an absent one.
func (c *ColumnOrder) UnmarshalJSON(b []byte) error {
	var m map[string][]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string][]string{}
	}
	*c = m
	return nil
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

// Fragment returns the link fragment (without '#') in format 2: the binding
// and the lines in compact form, then the database's credential ids, so
// the page offers only its passkeys. No separate approval id (the binding
// has it).
func (r Request) Fragment() (string, error) {
	return linkcodec.EncodeRequest(r.Binding, r.Lines, r.CredentialIDs)
}

// fromCompact is the request a format 2 link carries, its id read from the
// binding; Check refuses a binding that does not parse.
func fromCompact(binding string, lines []string, ids []passkey.Bytes) Request {
	r := Request{Binding: binding, Lines: lines, CredentialIDs: ids}
	if b, err := ParseBinding(binding); err == nil {
		r.ApprovalID = b.ApprovalID
	}
	return r
}

// URL returns the long approval link on the pages at base (links):
// <base>/approvals/<approvalId>#2.<request>.
func (r Request) URL(base string) (string, error) {
	frag, err := r.Fragment()
	if err != nil {
		return "", err
	}
	return links.Approval(base, r.ApprovalID) + "#" + frag, nil
}

// ParseRequest decodes an approval link fragment of either format, with or
// without '#', and checks it (Check).
func ParseRequest(fragment string) (Request, Binding, error) {
	r, err := linkcodec.DecodeRequest(fragment, MaxRows, fromCompact)
	if err != nil {
		return Request{}, Binding{}, invalid("approval request %v", err)
	}
	if r.RevealNonce != nil {
		return Request{}, Binding{}, invalid("a link carries no revealNonce: only the engine serves it")
	}
	if r.Columns != nil {
		return Request{}, Binding{}, invalid("a link carries no columns: only the engine serves them")
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

// DecodeResponse decodes the signed response the approval page posts (its
// JSON), strictly: an unknown field or a missing one is refused.
func DecodeResponse(raw []byte) (Response, error) {
	var r Response
	if err := passkey.DecodeStrict(raw, &r); err != nil {
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
