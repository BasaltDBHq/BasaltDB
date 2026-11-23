package channel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// KeyFileName is the engine key file in the engine's stateDir.
const KeyFileName = "channel.json"

const (
	// keyFileFormat is the only format.
	keyFileFormat = 1
	// keyFileMode: readable and writable by the engine's OS user only.
	keyFileMode = 0o600
	// keyFileMax bounds what is read; a valid file is well under 1 KiB.
	keyFileMax = 8 << 10
)

// ErrKeyFile marks every refusal of the key file. The contract's answer to
// one (VC-36) is the same whatever the reason: the file is left as it is,
// the channel stays off, no receipt is signed, and status reports
// vault.state KEY_ERROR. The error text names the path and the reason,
// never key bytes.
var ErrKeyFile = errors.New("engine key file refused")

var (
	engineIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	b64Pattern      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	sigPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
	spkiPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{122}$`)
)

// keyFile is channel.json (api/mcp/vault/channel-key-file.schema.json). The
// private keys stay json.RawMessage so this package can clear its own copies
// after use. Clearing is best effort: encoding/json and the runtime keep
// copies of their own that it cannot reach.
type keyFile struct {
	Format      *int            `json:"format"`
	EngineID    string          `json:"engineId"`
	CreatedAt   string          `json:"createdAt"`
	SigningKey  json.RawMessage `json:"signingKey"`
	BoxKey      json.RawMessage `json:"boxKey"`
	BoxKeySig   string          `json:"boxKeySig"`
	RotatedFrom *rotatedFrom    `json:"rotatedFrom,omitempty"`
}

// rotatedFrom is the latest rotation's statement (written by a later rotation). It is checked for shape here and kept as is.
type rotatedFrom struct {
	EngineID   string `json:"engineId"`
	SigningKey string `json:"signingKey"`
	At         string `json:"at"`
	Sig        string `json:"sig"`
}

func (f *keyFile) clear() {
	clear(f.SigningKey)
	clear(f.BoxKey)
}

func keyFileErr(path, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrKeyFile, path, fmt.Sprintf(format, args...))
}

func marshalKeyFile(k *EngineKeys) ([]byte, error) {
	signing, err := x509.MarshalPKCS8PrivateKey(k.signing)
	if err != nil {
		return nil, err
	}
	defer clear(signing)
	box, err := x509.MarshalPKCS8PrivateKey(k.box)
	if err != nil {
		return nil, err
	}
	defer clear(box)
	format := keyFileFormat
	f := keyFile{
		Format:     &format,
		EngineID:   k.engineID,
		CreatedAt:  k.createdAt.UTC().Format(time.RFC3339),
		SigningKey: quotedB64(signing),
		BoxKey:     quotedB64(box),
		BoxKeySig:  b64(k.boxKeySig),
	}
	defer f.clear()
	return json.MarshalIndent(f, "", "  ")
}

// quotedB64 is b's base64url as a JSON string, built in a byte slice that
// can be cleared (a Go string cannot). Best effort: json.MarshalIndent keeps
// copies of its own.
func quotedB64(b []byte) json.RawMessage {
	enc := base64.RawURLEncoding
	out := make([]byte, enc.EncodedLen(len(b))+2)
	out[0], out[len(out)-1] = '"', '"'
	enc.Encode(out[1:len(out)-1], b)
	return out
}

// unquoteB64 decodes a JSON string of base64url characters into bytes the
// caller clears.
func unquoteB64(raw json.RawMessage) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	inner := raw[1 : len(raw)-1]
	if !b64Pattern.Match(inner) {
		return nil, false
	}
	enc := base64.RawURLEncoding.Strict()
	out := make([]byte, enc.DecodedLen(len(inner)))
	n, err := enc.Decode(out, inner)
	if err != nil {
		clear(out)
		return nil, false
	}
	return out[:n], true
}

func decodeKeyFile(raw []byte) (*keyFile, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("not UTF-8")
	}
	var f keyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		f.clear()
		return nil, errors.New("not the key file's JSON shape")
	}
	if dec.More() {
		f.clear()
		return nil, errors.New("trailing data after the JSON")
	}
	return &f, nil
}

func parseKeyFile(path string, raw []byte) (*EngineKeys, error) {
	f, err := decodeKeyFile(raw)
	if err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	defer f.clear()
	createdAt, err := checkKeyFileShape(f)
	if err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	signing, box, err := parsePrivateKeys(f)
	if err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	k, err := newEngineKeys(signing, box, createdAt)
	if err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	if k.engineID != f.EngineID {
		return nil, keyFileErr(path, "engineId is not its signing key's id")
	}
	sig, err := Unb64(f.BoxKeySig)
	if err != nil {
		return nil, keyFileErr(path, "boxKeySig is not base64url")
	}
	if err := VerifySignature(&signing.PublicKey, ContextBoxKey, k.boxKeyStatement(), sig); err != nil {
		return nil, keyFileErr(path, "boxKeySig does not verify")
	}
	k.boxKeySig = sig
	return k, nil
}

// checkKeyFileShape is the schema's checks beyond the JSON shape.
func checkKeyFileShape(f *keyFile) (time.Time, error) {
	if f.Format == nil || *f.Format != keyFileFormat {
		return time.Time{}, errors.New("format must be 1")
	}
	if !engineIDPattern.MatchString(f.EngineID) {
		return time.Time{}, errors.New("engineId is not 22 base64url characters")
	}
	createdAt, err := time.Parse(time.RFC3339, f.CreatedAt)
	if err != nil {
		return time.Time{}, errors.New("createdAt is not an RFC 3339 time")
	}
	if !sigPattern.MatchString(f.BoxKeySig) {
		return time.Time{}, errors.New("boxKeySig is not 86 base64url characters")
	}
	if r := f.RotatedFrom; r != nil {
		_, atErr := time.Parse(time.RFC3339, r.At)
		if !engineIDPattern.MatchString(r.EngineID) || !spkiPattern.MatchString(r.SigningKey) ||
			!sigPattern.MatchString(r.Sig) || atErr != nil {
			return time.Time{}, errors.New("rotatedFrom does not have its schema's shape")
		}
	}
	return createdAt, nil
}

func parsePrivateKeys(f *keyFile) (*ecdsa.PrivateKey, *ecdh.PrivateKey, error) {
	signing, err := parseP256PKCS8(f.SigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signingKey: %w", err)
	}
	boxECDSA, err := parseP256PKCS8(f.BoxKey)
	if err != nil {
		return nil, nil, fmt.Errorf("boxKey: %w", err)
	}
	box, err := boxECDSA.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("boxKey: %w", err)
	}
	return signing, box, nil
}

func parseP256PKCS8(raw json.RawMessage) (*ecdsa.PrivateKey, error) {
	der, ok := unquoteB64(raw)
	if !ok {
		return nil, errors.New("not a base64url string")
	}
	defer clear(der)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("not a PKCS#8 private key")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ec, nil
}

// ParseKeyFile checks the content of a key file a caller read itself (the
// engine's key file store, statefile/keyfile, or a root process reading it
// through a directory it opened without following a link): the schema, the
// engineId and the box key's signature. The caller checks the file's
// owner, mode and size; path names the file in errors.
func ParseKeyFile(path string, raw []byte) (*EngineKeys, error) {
	if len(raw) > keyFileMax {
		return nil, keyFileErr(path, "%d bytes is too large for a key file", len(raw))
	}
	return parseKeyFile(path, raw)
}

// NewKeyFile is the content of a new key file with fresh keys, for the
// engine's key file store (statefile/keyfile) or a root process that writes
// it for the engine's user (CreateFile on a held directory).
func NewKeyFile(now func() time.Time) ([]byte, *EngineKeys, error) {
	keys, err := GenerateEngineKeys(now)
	if err != nil {
		return nil, nil, err
	}
	raw, err := marshalKeyFile(keys)
	if err != nil {
		return nil, nil, err
	}
	return raw, keys, nil
}

// KeyFileMode is the mode of the key file.
const KeyFileMode = keyFileMode

// KeyFileMax is the largest key file a reader takes (statefile/keyfile).
const KeyFileMax = keyFileMax
