// Package revert encodes and checks the codes of a revert authorisation
// (CONTRACT.md, Revert): the binding text the store builds, the revert lines
// it covers, the request in the revert link, and the response code the
// revert page outputs. It reuses the approval mechanism (owner decision D6):
// the same fragment encoding, rowsHash and challenge, and the same passkey
// checks. Nothing here decides whether a revert runs; the guard does, in
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

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
)

// KindRevert is the binding kind of a revert authorisation.
const KindRevert = "REVERT"

// MaxLines is the most lines, restored and skipped, of a revert applied in
// one call, and the most lines a revert link carries (decisions M3-9,
// N12-4, RSS-1). A plan with more lines is batched: the person signs it once and
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

func Invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", approval.ErrInvalid, fmt.Sprintf(format, args...))
}

// Select is a revert's scope descriptor as the binding carries it
// (CONTRACT.md, Revert, The scope descriptor): a scope narrowed to some
// agents (agent:<name>), runs and resources, nil for all. The store
// normalizes it; clients never re-serialize it.
type Select struct {
	Scope     Scope       `json:"scope"`
	ScopeID   uuid.UUID   `json:"scopeId"`
	Agents    []string    `json:"agents"`
	Runs      []uuid.UUID `json:"runs"`
	Resources []string    `json:"resources"`
}

// MaxFilter is the most runs, and the most resources, a descriptor lists
// (owner, Q10).
const MaxFilter = 20

func (s Select) check(name string) error {
	switch s.Scope {
	case ScopeChange, ScopeRun, ScopeTask:
	default:
		return Invalid("binding %s scope %q", name, s.Scope)
	}
	if s.ScopeID == uuid.Nil {
		return Invalid("binding %s names no scope id", name)
	}
	if s.Agents != nil && len(s.Agents) == 0 {
		return Invalid("binding %s names no agents", name)
	}
	if slices.ContainsFunc(s.Agents, func(a string) bool { return !approval.IsAgentName(a) }) {
		return Invalid("binding %s names an agent that is not agent:<name>", name)
	}
	if s.Runs != nil && s.Scope != ScopeTask {
		return Invalid("binding %s lists runs for a %s scope", name, s.Scope)
	}
	if len(s.Runs) > MaxFilter || len(s.Resources) > MaxFilter {
		return Invalid("binding %s lists more than %d runs or resources", name, MaxFilter)
	}
	return nil
}

// widenedFor reports whether s covers changes not made by agent: every
// agent (Agents nil) or another one.
func (s Select) widenedFor(agent string) bool {
	return s.Agents == nil || slices.ContainsFunc(s.Agents, func(a string) bool { return a != agent })
}

// Binding is the parsed binding text. The text itself, not this struct, is
// what the passkey signs: never re-serialize it.
type Binding struct {
	Kind     string                `json:"kind"`
	RevertID uuid.UUID             `json:"revertId"`
	Store    approval.BindingStore `json:"store"`
	// Select is the scope the person signs; Proposed what the agent asked
	// for, set only when a rescope changed it.
	Select   Select  `json:"select"`
	Proposed *Select `json:"proposed,omitempty"`
	// Widened is set when Select covers changes not made by RequestedBy;
	// AgentRows (lines per agent, keyed agent:<name>) is present exactly
	// then. RequestedBy is agent:<name> too.
	Widened     bool           `json:"widened"`
	AgentRows   map[string]int `json:"agentRows,omitempty"`
	Intent      string         `json:"intent"`
	Rows        int            `json:"rows"`
	Skipped     int            `json:"skipped"`
	RowsHash    string         `json:"rowsHash"`
	ExpiresAt   time.Time      `json:"expiresAt"`
	RequestedBy string         `json:"requestedBy"`
	// Batched and SampleHash are set only on a plan of more than MaxLines
	// lines (CONTRACT.md, Revert, Large plans).
	Batched    bool   `json:"batched,omitempty"`
	SampleHash string `json:"sampleHash,omitempty"`
}

// Empty reports a task proposal with no line of the requesting agent's own
// (CONTRACT.md, Revert): stored so the person may widen it, never signed as
// it is (apply_revert answers NOTHING_TO_REVERT).
func (b Binding) Empty() bool {
	return b.Select.Scope == ScopeTask && b.Rows == 0 && b.Skipped == 0 && !b.Batched
}

// checkScope checks select, proposed, widened and agentRows agree.
func (b Binding) checkScope() error {
	if err := b.Select.check("select"); err != nil {
		return err
	}
	if b.Proposed != nil {
		if err := b.Proposed.check("proposed"); err != nil {
			return err
		}
	}
	if !approval.IsAgentName(b.RequestedBy) {
		return Invalid("binding requestedBy %q is not agent:<name>", b.RequestedBy)
	}
	if b.Widened != b.Select.widenedFor(b.RequestedBy) {
		return Invalid("binding widened %t does not match its select and requestedBy", b.Widened)
	}
	if b.Widened != (b.AgentRows != nil) {
		return Invalid("binding agentRows goes with widened, and only with it")
	}
	for agent, n := range b.AgentRows {
		if !approval.IsAgentName(agent) || n < 0 {
			return Invalid("binding agentRows key %q is not agent:<name>", agent)
		}
	}
	return nil
}

// Lines is how many lines the binding covers.
func (b Binding) Lines() int {
	return b.Rows + b.Skipped
}

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
	if b.Kind != KindRevert {
		return Binding{}, Invalid("binding kind %q", b.Kind)
	}
	if err := approval.CheckStore(b.Store); err != nil {
		return Binding{}, err
	}
	if err := checkIntegers(text); err != nil {
		return Binding{}, err
	}
	if err := b.checkScope(); err != nil {
		return Binding{}, err
	}
	if b.Skipped < 0 {
		return Binding{}, Invalid("binding skipped %d", b.Skipped)
	}
	if b.Rows < 1 && !b.Empty() {
		return Binding{}, Invalid("binding rows %d: a revert restores at least one row", b.Rows)
	}
	if !isDigest(b.RowsHash) {
		return Binding{}, Invalid("binding rowsHash is not a sha256 hex digest")
	}
	if b.Batched {
		return b, b.checkBatched()
	}
	if b.SampleHash != "" {
		return Binding{}, Invalid("binding has a sampleHash but is not batched")
	}
	if b.Lines() > MaxLines {
		return Binding{}, Invalid("binding lines %d out of 1..%d; a larger plan is batched", b.Lines(), MaxLines)
	}
	return b, nil
}

// checkBatched checks a large plan's binding: more lines than one call
// takes, and a sample digest.
func (b Binding) checkBatched() error {
	if b.Lines() <= MaxLines {
		return Invalid("batched binding with %d lines: only a plan of more than %d lines is batched", b.Lines(), MaxLines)
	}
	if !isDigest(b.SampleHash) {
		return Invalid("binding sampleHash is not a sha256 hex digest")
	}
	return nil
}

// checkIntegers checks the binding's expiresAt and Basalt's own integers:
// rows, skipped and every value of agentRows in plain digits.
func checkIntegers(text string) error {
	if err := approval.CheckBasaltFields(text, "rows", "skipped"); err != nil {
		return err
	}
	var b struct {
		AgentRows map[string]json.RawMessage `json:"agentRows"`
	}
	if err := json.Unmarshal([]byte(text), &b); err != nil {
		return Invalid("binding: %v", err)
	}
	for agent, raw := range b.AgentRows {
		if !textrule.PlainInteger(raw) {
			return Invalid("binding agentRows %q is not a plain integer", agent)
		}
	}
	return nil
}

func isDigest(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == sha256.Size*2
}

// SampleShare is the room a batched plan's sample keeps for each kind of
// line: up to SampleShare SKIP lines and up to SampleShare RESTORE lines.
const SampleShare = MaxLines / 2

// SampleCounts returns how many SKIP and RESTORE lines a plan with skipped
// SKIP lines and rows RESTORE lines carries in its sample: up to
// SampleShare of each, and when one kind has fewer the other fills the
// rest, at most MaxLines in all (decision N12-4, amended by RSS-1). Both
// counts come from the signed binding, so a page can check them.
func SampleCounts(skipped, rows int) (skips, restores int) {
	skips = min(skipped, max(SampleShare, MaxLines-rows))
	restores = min(rows, MaxLines-skips)
	return skips, restores
}

// Request is the revert request: what the engine's local pages serve, and
// what a format 2 link expands to.
type Request struct {
	RevertID uuid.UUID `json:"revertId"`
	Binding  string    `json:"binding"`
	Lines    []string  `json:"lines"`
	// RescopeNonce is the nonce a widen proof signs, served only by the
	// engine, never carried in a long link.
	RescopeNonce passkey.Bytes `json:"rescopeNonce,omitempty"`
	// RevealNonce is the nonce a reveal proof signs (CONTRACT.md, Rows
	// hidden from the agent), served only by the engine, never carried in a
	// long link.
	RevealNonce   passkey.Bytes   `json:"revealNonce,omitempty"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
	// Columns orders each resource's fields as its store does, for the
	// page's display only (CONTRACT.md, Local pages): served only by the
	// engine, never signed, never carried in a link.
	Columns approval.ColumnOrder `json:"columns,omitempty"`
}

// Check parses the binding and checks the request against it: same revert,
// one line per row, as many RESTORE lines as the binding's rows, and the
// lines hash to rowsHash. For a batched plan the request carries the
// sample instead: MaxLines lines, SKIP lines first, as many of each kind as
// SampleCounts gives, hashing to sampleHash.
// The revert page makes the same checks before asking for a signature.
func (r Request) Check() (Binding, error) {
	b, err := ParseBinding(r.Binding)
	if err != nil {
		return Binding{}, err
	}
	if b.RevertID != r.RevertID {
		return Binding{}, Invalid("request is for revert %s, binding for %s", r.RevertID, b.RevertID)
	}
	if b.Batched {
		return b, r.checkSample(b)
	}
	if len(r.Lines) != b.Lines() {
		return Binding{}, Invalid("request has %d lines, binding %d", len(r.Lines), b.Lines())
	}
	if approval.RowsHash(r.Lines) != b.RowsHash {
		return Binding{}, Invalid("revert lines do not match the binding's rowsHash")
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
		return Binding{}, Invalid("request has %d RESTORE lines, binding %d rows", restore, b.Rows)
	}
	return b, nil
}

// checkSample checks a batched plan's request: the plan's sample, in
// order, matching the binding's sampleHash, with as many SKIP lines as
// SampleCounts gives for the binding's skipped and rows (the rest are
// RESTORE lines, since the sample has MaxLines lines).
func (r Request) checkSample(b Binding) error {
	if len(r.Lines) != MaxLines {
		return Invalid("request has %d lines, a batched plan's sample has %d", len(r.Lines), MaxLines)
	}
	if approval.RowsHash(r.Lines) != b.SampleHash {
		return Invalid("revert lines do not match the binding's sampleHash")
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
			return Invalid("the sample must list SKIP lines before RESTORE lines")
		}
		skips++
	}
	if want, _ := SampleCounts(b.Skipped, b.Rows); skips != want {
		return Invalid("request has %d SKIP lines, the binding's sample %d", skips, want)
	}
	return nil
}

// Fragment returns the link fragment (without '#') in format 2, as for
// approvals: the binding and the lines in compact form, then the
// database's credential ids, and no separate revert id.
// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): it refuses any other.
func (r Request) Fragment() (string, error) {
	if err := approval.CheckTexts(r.Binding, r.Lines...); err != nil {
		return "", err
	}
	return linkcodec.EncodeRequest(r.Binding, r.Lines, r.CredentialIDs)
}

// URL returns the long revert link on the pages at base (links):
// <base>/reverts/<revertId>#2.<request>.
func (r Request) URL(base string) (string, error) {
	frag, err := r.Fragment()
	if err != nil {
		return "", err
	}
	return links.Revert(base, r.RevertID) + "#" + frag, nil
}

// Response is what the revert page outputs after the person signs.
type Response struct {
	RevertID          uuid.UUID     `json:"revertId"`
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

// DecodeResponse decodes the signed response the revert page posts (its
// JSON), strictly: an unknown field or a missing one is refused.
func DecodeResponse(raw []byte) (Response, error) {
	var r Response
	if err := passkey.DecodeStrict(raw, &r); err != nil {
		return Response{}, Invalid("%v", err)
	}
	if len(r.CredentialID) == 0 || len(r.AuthenticatorData) == 0 || len(r.ClientDataJSON) == 0 || len(r.Signature) == 0 {
		return Response{}, Invalid("revert response is missing a field")
	}
	return r, nil
}
