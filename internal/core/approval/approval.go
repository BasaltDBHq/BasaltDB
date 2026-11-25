// Package approval encodes and checks the approval codes that travel between
// the engine, the static approval page and whoever relays the signed result
// (CONTRACT.md, Approvals): the binding text the store builds, the preview
// lines it covers, the request in the approval link, and the response code
// the page outputs. Nothing here decides whether an approval counts; the guard
// does, in basalt_meta.submit_approval and the guard's commit check.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
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

func Invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Binding is the parsed binding text (CONTRACT.md, Approvals, Binding
// text). The text itself, not this struct, is what the passkey signs: never
// re-serialize it.
type Binding struct {
	Kind       string       `json:"kind"`
	ApprovalID uuid.UUID    `json:"approvalId"`
	Store      BindingStore `json:"store"`
	// Agent is the agent that holds the write, agent:<name>.
	Agent          string      `json:"agent"`
	RunID          uuid.UUID   `json:"runId"`
	TaskID         *uuid.UUID  `json:"taskId"`
	Intent         string      `json:"intent"`
	Request        HeldRequest `json:"request"`
	AssignedFields []string    `json:"assignedFields"`
	Rows           int         `json:"rows"`
	RowsHash       string      `json:"rowsHash"`
	ExpiresAt      time.Time   `json:"expiresAt"`
}

// BindingStore is a binding's store part: the store's kind, a label only,
// and the name the store gives what the agent is bound to, for display.
type BindingStore struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// HeldRequest is the held request a binding carries, by family
// (CONTRACT.md, Stores, Request families): for SQL, the statement as the
// agent sent it and the values bound to $1, $2, ….
type HeldRequest struct {
	Kind      string            `json:"kind"`
	Statement string            `json:"statement"`
	Params    []json.RawMessage `json:"params"`
}

// RequestSQL is the SQL request family, the only one the engine runs.
const RequestSQL = "SQL"

// ParseBinding parses binding text for display and checks: the text rules,
// then the binding's keys and values.
func ParseBinding(text string) (Binding, error) {
	if err := textrule.Check(text); err != nil {
		return Binding{}, Invalid("binding: %v", err)
	}
	var b Binding
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Binding{}, Invalid("binding: %v", err)
	}
	if b.Kind != KindApprove {
		return Binding{}, Invalid("binding kind %q", b.Kind)
	}
	if err := CheckBasaltFields(text, "rows"); err != nil {
		return Binding{}, err
	}
	if b.Rows < 1 || b.Rows > MaxRows {
		return Binding{}, Invalid("binding rows %d out of 1..%d", b.Rows, MaxRows)
	}
	if _, err := hex.DecodeString(b.RowsHash); err != nil || len(b.RowsHash) != sha256.Size*2 {
		return Binding{}, Invalid("binding rowsHash is not a sha256 hex digest")
	}
	if err := CheckStore(b.Store); err != nil {
		return Binding{}, err
	}
	if !IsAgentName(b.Agent) {
		return Binding{}, Invalid("binding agent %q is not agent:<name>", b.Agent)
	}
	if b.Request.Kind != RequestSQL {
		return Binding{}, Invalid("binding request kind %q", b.Request.Kind)
	}
	if b.Request.Params == nil || b.AssignedFields == nil {
		return Binding{}, Invalid("binding request has no params or no assignedFields")
	}
	return b, nil
}

// CheckStore checks a binding's store part: a kind and a name.
func CheckStore(s BindingStore) error {
	if !storeKind.MatchString(s.Kind) || s.Name == "" {
		return Invalid("binding store needs a kind and a name")
	}
	return nil
}

// storeKind is the form of a store kind: SCREAMING_SNAKE_CASE. A page uses
// it as a label only, so any kind in that form is read.
var storeKind = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// CheckBasaltFields checks the values Basalt writes itself in a signed
// binding text: expiresAt in the exact timestamp form, and each named integer in
// plain digits (CONTRACT.md, Stores, Text rules).
func CheckBasaltFields(text string, integers ...string) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &keys); err != nil {
		return Invalid("binding: %v", err)
	}
	var expires string
	if err := json.Unmarshal(keys["expiresAt"], &expires); err != nil || !textrule.Timestamp.MatchString(expires) {
		return Invalid("binding expiresAt is not YYYY-MM-DDTHH:MM:SS.ffffffZ")
	}
	for _, name := range integers {
		if raw, ok := keys[name]; ok && !textrule.PlainInteger(raw) {
			return Invalid("binding %s is not a plain integer", name)
		}
	}
	return nil
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
// what a format 2 link expands to.
type Request struct {
	ApprovalID uuid.UUID `json:"approvalId"`
	Binding    string    `json:"binding"`
	Lines      []string  `json:"lines"`
	// RevealNonce is the nonce a reveal proof signs (Rows hidden from the
	// agent), served only by the engine, never carried in a long link.
	RevealNonce   passkey.Bytes   `json:"revealNonce,omitempty"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
	// Columns orders each resource's fields as its store does, for the
	// page's display only (CONTRACT.md, Local pages): served only by the
	// engine, never signed, never carried in a link.
	Columns ColumnOrder `json:"columns,omitempty"`
}

// ColumnOrder maps a resource, as the lines spell it, to its field names in
// the store's order. A present but null value decodes to an empty, non-nil
// map, so a link that names the field at all is told apart from one without
// it.
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
// one line per row, the lines hash to rowsHash, and every line follows the
// text rules and parses. The approval page makes the same checks before
// asking for a signature.
func (r Request) Check() (Binding, error) {
	b, err := ParseBinding(r.Binding)
	if err != nil {
		return Binding{}, err
	}
	if b.ApprovalID != r.ApprovalID {
		return Binding{}, Invalid("request is for approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	if len(r.Lines) != b.Rows {
		return Binding{}, Invalid("request has %d lines, binding %d rows", len(r.Lines), b.Rows)
	}
	if RowsHash(r.Lines) != b.RowsHash {
		return Binding{}, Invalid("preview lines do not match the binding's rowsHash")
	}
	for _, text := range r.Lines {
		if _, err := ParseLine(text); err != nil {
			return Binding{}, err
		}
	}
	return b, nil
}

// Fragment returns the link fragment (without '#') in format 2: the binding
// and the lines in compact form, then the database's credential ids, so
// the page offers only its passkeys. No separate approval id (the binding
// has it).
// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): it refuses any other.
func (r Request) Fragment() (string, error) {
	if err := CheckTexts(r.Binding, r.Lines...); err != nil {
		return "", err
	}
	return linkcodec.EncodeRequest(r.Binding, r.Lines, r.CredentialIDs)
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

// CheckTexts checks that every text the engine relays follows the text
// rules: the binding, then each line (or a plugin approval's settings).
func CheckTexts(binding string, lines ...string) error {
	if err := textrule.Check(binding); err != nil {
		return Invalid("binding: %v", err)
	}
	for i, l := range lines {
		if err := textrule.Check(l); err != nil {
			return Invalid("line %d: %v", i, err)
		}
	}
	return nil
}

// Response is what the approval page outputs after the person signs.
type Response struct {
	ApprovalID        uuid.UUID     `json:"approvalId"`
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
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
		return Response{}, Invalid("%v", err)
	}
	if len(r.CredentialID) == 0 || len(r.AuthenticatorData) == 0 || len(r.ClientDataJSON) == 0 || len(r.Signature) == 0 {
		return Response{}, Invalid("approval response is missing a field")
	}
	return r, nil
}
