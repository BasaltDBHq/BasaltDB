package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Control message types (api/mcp/vault/control-message.schema.json).
const (
	typeChallenge      = "CHALLENGE"
	typeAuth           = "AUTH"
	typeReady          = "READY"
	typeRegisterLink   = "REGISTER_LINK"
	typeUnregisterLink = "UNREGISTER_LINK"
	typeOK             = "OK"
	typeError          = "ERROR"
	typeSessionOpen    = "SESSION_OPEN"
	typeSessionClose   = "SESSION_CLOSE"
)

// CodeLinkConflict is the ERROR code of a token another engine registered.
const CodeLinkConflict = "LINK_CONFLICT"

// authVersion is AUTH's only version.
const authVersion = 1

// maxRef is the largest ref, 2^53 - 1, so it survives a JSON number in a browser.
const maxRef = 1<<53 - 1

// closeNormal is the WebSocket normal closure, which SESSION_CLOSE may carry.
const closeNormal = 1000

// errorCodes are the ERROR codes the Vault may send.
var errorCodes = map[string]bool{
	CodeLinkConflict:  true,
	"LINK_LIMIT":      true,
	"INVALID_EXPIRY":  true,
	"UNKNOWN_SESSION": true,
	"RATE_LIMITED":    true,
	"PROTOCOL":        true,
}

// errMalformed is a control message that is not one of the schema's shapes.
var errMalformed = errors.New("vault: malformed control message")

// challengeMsg is CHALLENGE, Vault to engine.
type challengeMsg struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// authMsg is AUTH, engine to Vault.
type authMsg struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	Sig     string `json:"sig"`
}

// registerLinkMsg is REGISTER_LINK, engine to Vault. It carries the link's
// token only: never its secret or psk.
type registerLinkMsg struct {
	Type      string `json:"type"`
	Ref       int64  `json:"ref"`
	LinkToken string `json:"linkToken"`
	ExpiresAt string `json:"expiresAt"`
}

// unregisterLinkMsg is UNREGISTER_LINK, engine to Vault.
type unregisterLinkMsg struct {
	Type      string `json:"type"`
	Ref       int64  `json:"ref"`
	LinkToken string `json:"linkToken"`
}

// typeOnly is READY, and the head every control message is read by.
type typeOnly struct {
	Type string `json:"type"`
}

// okMsg is OK, Vault to engine.
type okMsg struct {
	Type string `json:"type"`
	Ref  *int64 `json:"ref"`
}

// errorMsg is ERROR, Vault to engine. Ref is absent when it answers no request.
type errorMsg struct {
	Type string `json:"type"`
	Ref  *int64 `json:"ref"`
	Code string `json:"code"`
}

// sessionOpenMsg is SESSION_OPEN, Vault to engine.
type sessionOpenMsg struct {
	Type      string `json:"type"`
	SID       string `json:"sid"`
	LinkToken string `json:"linkToken"`
}

// sessionCloseMsg is SESSION_CLOSE, either way.
type sessionCloseMsg struct {
	Type string `json:"type"`
	SID  string `json:"sid"`
	Code *int   `json:"code"`
}

// control is one control message from the Vault, checked against its shape.
// Exactly one of its fields is set, the one its type names.
type control struct {
	typ          string
	challenge    string
	ok           *okMsg
	err          *errorMsg
	sessionOpen  *sessionOpen
	sessionClose *sessionClose
}

// sessionOpen is a checked SESSION_OPEN.
type sessionOpen struct {
	sid   sid
	token channel.LinkToken
}

// sessionClose is a checked SESSION_CLOSE.
type sessionClose struct {
	sid  sid
	code int
}

// parseControl reads a control message strictly: a known type, no unknown
// field, nothing after the object, and every field of its shape valid.
// Anything else is errMalformed, which closes the socket with PROTOCOL.
func parseControl(data []byte) (control, error) {
	var head typeOnly
	if err := json.Unmarshal(data, &head); err != nil {
		return control{}, errMalformed
	}
	c := control{typ: head.Type}
	var err error
	switch head.Type {
	case typeChallenge:
		err = c.readChallenge(data)
	case typeReady:
		err = decodeStrict(data, &typeOnly{})
	case typeOK:
		err = c.readOK(data)
	case typeError:
		err = c.readError(data)
	case typeSessionOpen:
		err = c.readSessionOpen(data)
	case typeSessionClose:
		err = c.readSessionClose(data)
	default:
		// AUTH, REGISTER_LINK and UNREGISTER_LINK are the engine's to send;
		// anything else is unknown.
		err = errMalformed
	}
	if err != nil {
		return control{}, err
	}
	return c, nil
}

func (c *control) readChallenge(data []byte) error {
	var m challengeMsg
	if err := decodeStrict(data, &m); err != nil {
		return err
	}
	if _, err := decodeFixed(m.Challenge, challengeLen); err != nil {
		return errMalformed
	}
	c.challenge = m.Challenge
	return nil
}

func (c *control) readOK(data []byte) error {
	var m okMsg
	if err := decodeStrict(data, &m); err != nil {
		return err
	}
	if m.Ref == nil || !validRef(*m.Ref) {
		return errMalformed
	}
	c.ok = &m
	return nil
}

func (c *control) readError(data []byte) error {
	var m errorMsg
	if err := decodeStrict(data, &m); err != nil {
		return err
	}
	if (m.Ref != nil && !validRef(*m.Ref)) || !errorCodes[m.Code] {
		return errMalformed
	}
	c.err = &m
	return nil
}

func (c *control) readSessionOpen(data []byte) error {
	var m sessionOpenMsg
	if err := decodeStrict(data, &m); err != nil {
		return err
	}
	id, err := parseSID(m.SID)
	if err != nil {
		return errMalformed
	}
	token, err := channel.ParseLinkToken(m.LinkToken)
	if err != nil {
		return errMalformed
	}
	c.sessionOpen = &sessionOpen{sid: id, token: token}
	return nil
}

func (c *control) readSessionClose(data []byte) error {
	var m sessionCloseMsg
	if err := decodeStrict(data, &m); err != nil {
		return err
	}
	id, err := parseSID(m.SID)
	if err != nil || m.Code == nil || !sessionCloseCode(*m.Code) {
		return errMalformed
	}
	c.sessionClose = &sessionClose{sid: id, code: *m.Code}
	return nil
}

// sessionCloseCode is 1000 or a code of the registry.
func sessionCloseCode(code int) bool {
	return code == closeNormal || (code >= int(channel.ErrProtocol) && code <= int(channel.ErrEngineShutdown))
}

func validRef(ref int64) bool { return ref >= 1 && ref <= maxRef }

// decodeStrict decodes one JSON object into v, refusing unknown fields and
// trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errMalformed
	}
	if dec.More() {
		return errMalformed
	}
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeFixed decodes strict base64url without padding of exactly n bytes.
func decodeFixed(s string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != n {
		return nil, errMalformed
	}
	return b, nil
}
