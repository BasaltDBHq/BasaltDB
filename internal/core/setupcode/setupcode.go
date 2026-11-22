// Package setupcode encodes, decodes and checks the setup code that carries
// an install from the bot's machine to the person's own computer
// (CONTRACT.md, Setup from your laptop):
//
//	basalt-setup.1.<b64url(deflate-raw(json))>.<check>
//
// The code never holds the agent's password (its SCRAM-SHA-256 verifier
// instead, which is sensitive: CONTRACT.md, The setup code) and never
// anything of the admin.
// The code-maker writes every field, so nothing in it is trusted: Decode
// refuses anything outside setup-code.schema.json and the rules the schema
// cannot state, and CheckLocal and CheckDatabase apply the clock and the
// database's state on the person's computer.
package setupcode

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Code layout (CONTRACT.md, The setup code).
const (
	// Prefix starts every setup code.
	Prefix = "basalt-setup."
	// version is the code layout version after Prefix.
	version = "1."
	// Format is the payload's format field.
	Format = 1
	// MaxCodeLen is the longest code basalt init --remote hands out.
	MaxCodeLen = 1500
	// MaxInputBytes caps the pasted text, whitespace included, before any
	// work: a real code is at most MaxCodeLen.
	MaxInputBytes = 64 << 10
	// MaxPayloadBytes caps the inflated JSON, so a crafted code cannot
	// inflate without bound.
	MaxPayloadBytes = 64 << 10
	// checkBytes of sha256 make the check: 6 base64url characters.
	checkBytes = 4
	// fingerprintBytes of sha256 make the fingerprint (80 bits).
	fingerprintBytes = 10
	// fingerprintGroup is the hex digits per group in the fingerprint.
	fingerprintGroup = 4
	fingerprintLabel = "basalt-setup-fingerprint.2\n"
)

// Kind is what a code sets up (CO-14).
type Kind string

// Kinds.
const (
	KindInstall Kind = "INSTALL"
	KindAgent   Kind = "AGENT"
	KindUpgrade Kind = "UPGRADE"
)

// ErrCodeTooLong is returned by Encode for a code over MaxCodeLen.
var ErrCodeTooLong = errors.New("this setup code is too long: name fewer tables")

// Payload is the JSON inside a setup code (setup-code.schema.json). Field
// order is the schema's key order, which the encoder writes.
type Payload struct {
	Format  int    `json:"format"`
	SetupID string `json:"setupId"`
	Kind    Kind   `json:"kind"`
	Prefix  string `json:"prefix"`
	// Target is nil in a connect-only code (CONTRACT.md, Connect-only
	// setup codes): its database is the one the person pastes on the
	// connect page.
	Target    *Target `json:"target,omitempty"`
	Guard     Guard   `json:"guard"`
	Build     string  `json:"build"`
	Agent     *Agent  `json:"agent,omitempty"`
	ExpiresAt string  `json:"expiresAt"`
	// Engine is the engine's identity key (M4.1, CO-18), absent when the
	// code-maker's key file could not be read.
	Engine *Engine `json:"engine,omitempty"`
	// TrustPin is the SHA-256 (DER, 64 lowercase hex digits) of the
	// certificate the bot's engine has pinned for the target's host, absent
	// when it has none (CONTRACT.md, The setup code, trustPin): a hint for
	// the connect page's trust step that adds no trust. Only in a code with
	// target, of kind AGENT or UPGRADE (setup-code.schema.json). Last in the
	// schema's order.
	TrustPin string `json:"trustPin,omitempty"`
}

// Engine is the engine part of a code: its signing key, which the person's
// computer records in basalt_meta (version 33).
type Engine struct {
	// PublicKey is the signing key's SPKI DER, base64url without padding.
	PublicKey string `json:"publicKey"`
}

// Target is the database the bot's engine connects to.
type Target struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SupabaseRef string `json:"supabaseRef,omitempty"`
}

// Guard is the basalt_meta version the bot read (From, 0 when none) and
// the one its build installs (To).
type Guard struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Agent is the agent part; absent for UPGRADE. Write and Read are absent
// (nil) when AllTables is set, and present, possibly empty, otherwise.
type Agent struct {
	Name      string     `json:"name"`
	Write     []string   `json:"write,omitzero"`
	Read      []string   `json:"read,omitzero"`
	AllTables *AllTables `json:"allTables,omitempty"`
	Verifier  string     `json:"verifier,omitempty"`
	// StatementTimeoutMs is the agent role's statement timeout.
	StatementTimeoutMs int64 `json:"statementTimeoutMs"`
}

// AllTables is agent.allTables: write access to every table in Schemas
// that the admin role owns when the setup runs (public only).
type AllTables struct {
	Schemas []string `json:"schemas"`
}

// ConnectOnly reports whether p is a connect-only code: no target, so only
// the connect page runs it, with the database the person pastes there.
func (p Payload) ConnectOnly() bool { return p.Target == nil }

// Encode validates p and returns its code: compact JSON in the schema's
// key order, deflated at level 9, base64url without padding, and the
// check. Nil table lists are written as empty lists.
func Encode(p Payload) (string, error) {
	p = p.normalized()
	if err := p.Validate(); err != nil {
		return "", err
	}
	js, err := p.compactJSON()
	if err != nil {
		return "", fmt.Errorf("setup code: %w", err)
	}
	var z bytes.Buffer
	w, err := flate.NewWriter(&z, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("setup code: %w", err)
	}
	if _, err := w.Write(js); err != nil {
		return "", fmt.Errorf("setup code: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("setup code: %w", err)
	}
	body := Prefix + version + base64.RawURLEncoding.EncodeToString(z.Bytes())
	code := body + "." + check(body)
	if len(code) > MaxCodeLen {
		return "", ErrCodeTooLong
	}
	return code, nil
}

// normalized is p with nil table lists as empty lists, as the code
// writes them, unless the agent asks for all tables (then they are absent).
func (p Payload) normalized() Payload {
	if p.Agent != nil && p.Agent.AllTables == nil {
		a := *p.Agent
		a.Write = nonNil(a.Write)
		a.Read = nonNil(a.Read)
		p.Agent = &a
	}
	return p
}

// compactJSON is the payload's JSON as a code carries it: compact, in the
// schema's key order, HTML characters unescaped.
func (p Payload) compactJSON() ([]byte, error) {
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	// Encoder.Encode ends with a newline: not part of the compact JSON.
	return bytes.TrimSuffix(js.Bytes(), []byte("\n")), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func check(body string) string {
	sum := sha256.Sum256([]byte(body))
	return base64.RawURLEncoding.EncodeToString(sum[:checkBytes])
}

// Decode reads a pasted setup code. Every whitespace character is dropped
// first, so a wrapped copy still decodes. Refusals, in this order:
// NOT_A_SETUP_CODE, INVALID (layout version 1 with nothing after it),
// UNSUPPORTED_FORMAT (layout version), DAMAGED (check), INVALID
// (base64url, deflate, the 64 KiB cap, JSON, a duplicate key),
// UNSUPPORTED_FORMAT (format), INVALID (schema and rules).
func Decode(code string) (Payload, error) {
	if len(code) > MaxInputBytes {
		return Payload{}, refuse(RefusalInvalid, "the pasted text is far longer than any setup code")
	}
	code = dropSpace(code)
	rest, ok := strings.CutPrefix(code, Prefix)
	if !ok {
		return Payload{}, refuse(RefusalNotASetupCode, "")
	}
	if rest == strings.TrimSuffix(version, ".") {
		// basalt-setup.1 is this layout cut short, not a newer one.
		return Payload{}, refuse(RefusalInvalid, "no payload")
	}
	if !strings.HasPrefix(rest, version) {
		return Payload{}, refuse(RefusalUnsupportedFormat, "")
	}
	dot := strings.LastIndexByte(code, '.')
	body, sum := code[:dot], code[dot+1:]
	if sum != check(body) {
		return Payload{}, refuse(RefusalDamaged, "")
	}
	encoded, ok := strings.CutPrefix(body, Prefix+version)
	if !ok || encoded == "" {
		return Payload{}, refuse(RefusalInvalid, "no payload")
	}
	raw, err := inflate(encoded)
	if err != nil {
		return Payload{}, err
	}
	return decodePayload(raw)
}

func dropSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func inflate(encoded string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, refuse(RefusalInvalid, "payload is not base64url")
	}
	// bytes.Reader is an io.ByteReader, so flate reads no further than the
	// end of the stream: whatever is left in src is trailing data.
	src := bytes.NewReader(compressed)
	r := flate.NewReader(src)
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, MaxPayloadBytes+1))
	switch {
	case err != nil:
		return nil, refuse(RefusalInvalid, "payload does not inflate")
	case len(raw) > MaxPayloadBytes:
		return nil, refuse(RefusalInvalid, "payload inflates past 64 KiB")
	case src.Len() != 0:
		return nil, refuse(RefusalInvalid, "payload has data after the deflate stream")
	}
	return raw, nil
}

// decodePayload parses the JSON strictly: no key twice in one object,
// format first (a newer format may have keys this build does not know),
// then a typed decode that must hold exactly what the JSON holds. Go's
// decoder keeps the last of duplicate keys, matches keys
// case-insensitively, reads null as absent and replaces invalid UTF-8; the
// duplicate check, and comparing the typed value, encoded again, with the
// generic decode, refuse all four.
func decodePayload(raw []byte) (Payload, error) {
	if !utf8.Valid(raw) {
		return Payload{}, refuse(RefusalInvalid, "payload is not UTF-8")
	}
	generic, err := unmarshalGeneric(raw)
	if err != nil {
		return Payload{}, refuse(RefusalInvalid, "payload is not a JSON object")
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return Payload{}, refuse(RefusalInvalid, "payload has a duplicate key")
	}
	if !isFormat1(generic["format"]) {
		return Payload{}, refuse(RefusalUnsupportedFormat, "")
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, refuse(RefusalInvalid, "payload does not match the schema")
	}
	again, err := json.Marshal(p)
	if err != nil {
		return Payload{}, refuse(RefusalInvalid, "payload does not match the schema")
	}
	typed, err := unmarshalGeneric(again)
	if err != nil || !reflect.DeepEqual(generic, typed) {
		return Payload{}, refuse(RefusalInvalid, "payload does not match the schema")
	}
	if err := p.Validate(); err != nil {
		return Payload{}, err
	}
	return p, nil
}

func unmarshalGeneric(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("null")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return m, nil
}

// jsonContainer is one open object or array while walking JSON tokens;
// keys is nil for an array.
type jsonContainer struct {
	keys    map[string]struct{}
	wantKey bool
}

// checkNoDuplicateKeys walks raw's tokens and fails on an object that holds
// a key twice, at any depth. raw is already known to be valid JSON.
func checkNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonContainer
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(stack); n > 0 && stack[n-1].wantKey {
			// Token returns an object's keys as strings; the only other
			// token where a key is due is the object's closing brace.
			if key, ok := tok.(string); ok {
				if _, seen := stack[n-1].keys[key]; seen {
					return fmt.Errorf("duplicate key %q", key)
				}
				stack[n-1].keys[key] = struct{}{}
				stack[n-1].wantKey = false
				continue
			}
		}
		d, ok := tok.(json.Delim)
		if !ok {
			valueDone()
			continue
		}
		switch d {
		case '{':
			stack = append(stack, &jsonContainer{keys: map[string]struct{}{}, wantKey: true})
		case '[':
			stack = append(stack, &jsonContainer{})
		default: // '}' or ']'
			stack = stack[:len(stack)-1]
			valueDone()
		}
	}
}

func isFormat1(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	f, err := n.Float64()
	return err == nil && f == Format
}

// Role is the agent's role, <prefix>_agent_<name>; empty without an agent.
func (p Payload) Role() string {
	if p.Agent == nil {
		return ""
	}
	return p.Prefix + "_agent_" + p.Agent.Name
}

// Fingerprint is the setup fingerprint: the first 10 bytes of
// sha256("basalt-setup-fingerprint.2\n" + the payload's compact JSON) in
// lowercase hex, five groups of four. The JSON is the one Encode writes
// (schema key order), rebuilt from the decoded payload, so it covers every
// field of the code (agent, tables, kind, timeout, target, guard, expiry)
// whatever key order or deflate stream the code-maker used. A matching aid
// for the person, not proof of who made the code.
func (p Payload) Fingerprint() string {
	js, err := p.normalized().compactJSON()
	if err != nil {
		// Unreachable: the payload is plain strings, numbers and lists.
		panic("setupcode: payload JSON: " + err.Error())
	}
	sum := sha256.Sum256(append([]byte(fingerprintLabel), js...))
	h := hex.EncodeToString(sum[:fingerprintBytes])
	groups := make([]string, 0, len(h)/fingerprintGroup)
	for i := 0; i < len(h); i += fingerprintGroup {
		groups = append(groups, h[i:i+fingerprintGroup])
	}
	return strings.Join(groups, " ")
}

// ExpiresTime parses ExpiresAt.
func (p Payload) ExpiresTime() (time.Time, error) {
	t, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return time.Time{}, refuse(RefusalInvalid, "expiresAt is not a time")
	}
	return t, nil
}

// CreatedAt is the setupId's UUIDv7 time: its first 48 bits, milliseconds
// since the epoch.
func (p Payload) CreatedAt() (time.Time, error) {
	if !setupIDPattern.MatchString(p.SetupID) {
		return time.Time{}, refuse(RefusalInvalid, "setupId is not a UUIDv7")
	}
	ms, err := strconv.ParseInt(strings.ReplaceAll(p.SetupID, "-", "")[:uuidTimeHex], 16, 64)
	if err != nil {
		return time.Time{}, refuse(RefusalInvalid, "setupId is not a UUIDv7")
	}
	return time.UnixMilli(ms).UTC(), nil
}
