// Package revert encodes and checks the codes of a revert authorisation
// (CONTRACT.md, Revert): the binding text Postgres builds, the revert lines
// it covers, the request in the revert link, and the response code the
// revert page outputs. It reuses the approval mechanism (owner decision D6):
// the same fragment encoding, rowsHash and challenge, and the same passkey
// checks. Nothing here decides whether a revert runs; Postgres does, in
// basalt_meta.apply_revert.
package revert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// Code prefixes and the page URL (CONTRACT.md, Revert, Lines, binding and
// codes).
const (
	// RequestPrefix starts the revert link's fragment, as for approvals.
	RequestPrefix = approval.RequestPrefix
	// ResponsePrefix starts the code the revert page outputs.
	ResponsePrefix = "basalt-revert.1."
	// PageURL is the static revert page.
	PageURL = "https://basaltvault.app/revert/"
)

// KindRevert is the binding kind of a revert authorisation.
const KindRevert = "REVERT"

// MaxLines is the most lines, restored and skipped, of a revert applied in
// one call, and the most lines a revert link carries (decisions M3-9,
// N12-4). A plan with more lines is batched: the person signs it once and
// the agent applies it in batches.
const MaxLines = 1000

// MaxBatch is the most lines one apply_revert_batch call applies (decision
// N12-3).
const MaxBatch = 200

// ApplyWindow is how long after the person's signature a batched plan may
// still be applied (decision N12-2).
const ApplyWindow = 24 * time.Hour

// Scope is what a revert covers.
type Scope string

// Scopes (CONTRACT.md, Revert).
const (
	ScopeChange Scope = "CHANGE"
	ScopeRun    Scope = "RUN"
	ScopeTask   Scope = "TASK"
)

// ErrInvalid wraps every reason a revert code, binding or line is refused.
// It is the approval package's error: both codes come from the same
// mechanism and fail the same way.
var ErrInvalid = approval.ErrInvalid

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Challenge is the WebAuthn challenge for a binding: sha256 of its UTF-8
// bytes, as for approvals.
func Challenge(bindingText string) []byte {
	return approval.Challenge(bindingText)
}

// RowsHash is the lowercase hex sha256 of every revert line, restored and
// skipped, joined by "\n" (decision M3-6).
func RowsHash(lines []string) string {
	return approval.RowsHash(lines)
}

// Binding is the parsed binding text. The text itself, not this struct, is
// what the passkey signs: never re-serialize it.
type Binding struct {
	Kind        string    `json:"kind"`
	RevertID    uuid.UUID `json:"revertId"`
	Database    string    `json:"database"`
	Scope       Scope     `json:"scope"`
	ScopeID     uuid.UUID `json:"scopeId"`
	Agents      []string  `json:"agents"`
	Intent      string    `json:"intent"`
	Rows        int       `json:"rows"`
	Skipped     int       `json:"skipped"`
	RowsHash    string    `json:"rowsHash"`
	ExpiresAt   time.Time `json:"expiresAt"`
	RequestedBy string    `json:"requestedBy"`
	// Batched and SampleHash are set only on a plan of more than MaxLines
	// lines (CONTRACT.md, Revert, Large plans).
	Batched    bool   `json:"batched,omitempty"`
	SampleHash string `json:"sampleHash,omitempty"`
}

// Lines is how many lines the binding covers.
func (b Binding) Lines() int {
	return b.Rows + b.Skipped
}

// ParseBinding parses binding text for display and checks.
func ParseBinding(text string) (Binding, error) {
	var b Binding
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Binding{}, invalid("binding: %v", err)
	}
	if b.Kind != KindRevert {
		return Binding{}, invalid("binding kind %q", b.Kind)
	}
	switch b.Scope {
	case ScopeChange, ScopeRun, ScopeTask:
	default:
		return Binding{}, invalid("binding scope %q", b.Scope)
	}
	if len(b.Agents) == 0 {
		return Binding{}, invalid("binding names no agents")
	}
	if b.Rows < 1 {
		return Binding{}, invalid("binding rows %d: a revert restores at least one row", b.Rows)
	}
	if b.Skipped < 0 {
		return Binding{}, invalid("binding skipped %d", b.Skipped)
	}
	if !isDigest(b.RowsHash) {
		return Binding{}, invalid("binding rowsHash is not a sha256 hex digest")
	}
	if b.Batched {
		return b, b.checkBatched()
	}
	if b.SampleHash != "" {
		return Binding{}, invalid("binding has a sampleHash but is not batched")
	}
	if b.Lines() > MaxLines {
		return Binding{}, invalid("binding lines %d out of 1..%d; a larger plan is batched", b.Lines(), MaxLines)
	}
	return b, nil
}

// checkBatched checks a large plan's binding: more lines than one call
// takes, and a sample digest.
func (b Binding) checkBatched() error {
	if b.Lines() <= MaxLines {
		return invalid("batched binding with %d lines: only a plan of more than %d lines is batched", b.Lines(), MaxLines)
	}
	if !isDigest(b.SampleHash) {
		return invalid("binding sampleHash is not a sha256 hex digest")
	}
	return nil
}

func isDigest(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == sha256.Size*2
}

// Sample returns the lines a revert link carries for a plan whose lines are
// in signed order: SKIP lines first, then RESTORE lines, each group in
// signed order, at most MaxLines (decision N12-4). Postgres builds the same
// sample in prepare_revert.
func Sample(lines []string) ([]string, error) {
	skips := make([]string, 0, len(lines))
	restores := make([]string, 0, len(lines))
	for _, text := range lines {
		l, err := ParseLine(text)
		if err != nil {
			return nil, err
		}
		if l.Action == ActionSkip {
			skips = append(skips, text)
			continue
		}
		restores = append(restores, text)
	}
	out := slices.Concat(skips, restores)
	return out[:min(len(out), MaxLines)], nil
}

// Request is what basalt revert puts in the revert link.
type Request struct {
	RevertID      uuid.UUID       `json:"revertId"`
	Binding       string          `json:"binding"`
	Lines         []string        `json:"lines"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
}

// Check parses the binding and checks the request against it: same revert,
// one line per row, as many RESTORE lines as the binding's rows, and the
// lines hash to rowsHash. For a batched plan the request carries the
// sample instead: MaxLines lines, SKIP lines first, hashing to sampleHash.
// The revert page makes the same checks before asking for a signature.
func (r Request) Check() (Binding, error) {
	b, err := ParseBinding(r.Binding)
	if err != nil {
		return Binding{}, err
	}
	if b.RevertID != r.RevertID {
		return Binding{}, invalid("request is for revert %s, binding for %s", r.RevertID, b.RevertID)
	}
	if b.Batched {
		return b, r.checkSample(b)
	}
	if len(r.Lines) != b.Lines() {
		return Binding{}, invalid("request has %d lines, binding %d", len(r.Lines), b.Lines())
	}
	if RowsHash(r.Lines) != b.RowsHash {
		return Binding{}, invalid("revert lines do not match the binding's rowsHash")
	}
	restore := 0
	for _, text := range r.Lines {
		l, err := ParseLine(text)
		if err != nil {
			return Binding{}, err
		}
		if l.Action == ActionRestore {
			restore++
		}
	}
	if restore != b.Rows {
		return Binding{}, invalid("request has %d RESTORE lines, binding %d rows", restore, b.Rows)
	}
	return b, nil
}

// checkSample checks a batched plan's request: the plan's sample, in
// order, matching the binding's sampleHash and skipped count.
func (r Request) checkSample(b Binding) error {
	if len(r.Lines) != MaxLines {
		return invalid("request has %d lines, a batched plan's sample has %d", len(r.Lines), MaxLines)
	}
	if RowsHash(r.Lines) != b.SampleHash {
		return invalid("revert lines do not match the binding's sampleHash")
	}
	skips, restoring := 0, false
	for _, text := range r.Lines {
		l, err := ParseLine(text)
		if err != nil {
			return err
		}
		if l.Action == ActionRestore {
			restoring = true
			continue
		}
		if restoring {
			return invalid("the sample must list SKIP lines before RESTORE lines")
		}
		skips++
	}
	if want := min(b.Skipped, MaxLines); skips != want {
		return invalid("request has %d SKIP lines, the binding's sample %d", skips, want)
	}
	return nil
}

// Fragment returns the link fragment (without '#'):
// 1.<base64url(deflate-raw(json))>.
func (r Request) Fragment() (string, error) {
	return approval.EncodeFragment(r)
}

// URL returns the revert link on page (PageURL outside tests and local
// development).
func (r Request) URL(page string) (string, error) {
	frag, err := r.Fragment()
	if err != nil {
		return "", err
	}
	return page + "#" + frag, nil
}

// ParseRequest decodes a revert link fragment, with or without '#', and
// checks it (Check).
func ParseRequest(fragment string) (Request, Binding, error) {
	var r Request
	if err := approval.DecodeFragment(fragment, "revert request", &r); err != nil {
		return Request{}, Binding{}, err
	}
	b, err := r.Check()
	if err != nil {
		return Request{}, Binding{}, err
	}
	return r, b, nil
}

// Response is what the revert page outputs after the person signs.
type Response struct {
	RevertID          uuid.UUID     `json:"revertId"`
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

// NewResponse wraps an assertion for revertID.
func NewResponse(revertID uuid.UUID, a passkey.Assertion) Response {
	return Response{
		RevertID:          revertID,
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

// Code returns the text the person copies: basalt-revert.1.<base64url(json)>.
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
		return Response{}, invalid("revert response is missing a field")
	}
	return r, nil
}

// Verify checks a response against the binding text it should sign and the
// stored passkey, the way basalt_meta.apply_revert does (without the
// revert's state and expiry, which only Postgres knows). It returns the new
// signature counter.
func Verify(bindingText string, cred passkey.Credential, r Response) (uint32, error) {
	b, err := ParseBinding(bindingText)
	if err != nil {
		return 0, err
	}
	if b.RevertID != r.RevertID {
		return 0, invalid("response is for revert %s, binding for %s", r.RevertID, b.RevertID)
	}
	count, err := passkey.VerifyAssertion(cred, Challenge(bindingText), r.Assertion())
	if err != nil {
		return 0, fmt.Errorf("revert %s: %w", r.RevertID, err)
	}
	return count, nil
}
