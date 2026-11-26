package channel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// SigningContext is the line every input the engine's signing key signs
// starts with (CONTRACT.md, Vault channel, Primitives and encodings), so no
// signature made for one purpose verifies as another. A new context is a
// contract change.
type SigningContext string

// The signing contexts.
const (
	ContextVaultAuth SigningContext = "basalt-vault-engine.1\n"
	ContextSession   SigningContext = "basalt-vault-session-sig.1\n"
	ContextReceipt   SigningContext = "basalt-receipt.1\n"
	ContextBoxKey    SigningContext = "basalt-engine-box-key.1\n"
	ContextRotate    SigningContext = "basalt-engine-rotate.1\n"
	// ContextConnectCollect signs a request for a connect-only setup's
	// address (CONTRACT.md, Connect, The address hand-off).
	ContextConnectCollect SigningContext = "basalt-connect-collect.1\n"
	// ContextConnectReach signs the engine's report on whether it reached a
	// collected address (CONTRACT.md, Connect, The reach check).
	ContextConnectReach SigningContext = "basalt-connect-reach.1\n"
)

// ConnectAudience is the connect service's host, the audience every
// basalt-connect-collect.1 and basalt-connect-reach.1 signature names.
const ConnectAudience = "connect.basaltvault.app"

// ConnectCollectBody is what follows the basalt-connect-collect.1 line:
// the audience, the setupId, the setup fingerprint as printed and the time
// (RFC 3339 UTC, whole seconds), one per line, with nothing after the time.
func ConnectCollectBody(setupID, fingerprint, at string) []byte {
	return []byte(ConnectAudience + "\n" + setupID + "\n" + fingerprint + "\n" + at)
}

// ConnectReachBody is what follows the basalt-connect-reach.1 line: the
// collect body's lines, then the address in its canonical form (host,
// port, database, Supabase ref; the caller lowercases the host and the
// ref), the result and the reason, one per line, with nothing after the
// reason. An absent ref and the reason of a REACHABLE report are empty
// lines.
func ConnectReachBody(setupID, fingerprint, at, host string, port int, database, ref, result, reason string) []byte {
	return []byte(string(ConnectCollectBody(setupID, fingerprint, at)) + "\n" + host + "\n" + strconv.Itoa(port) + "\n" +
		database + "\n" + ref + "\n" + result + "\n" + reason)
}

func (c SigningContext) valid() bool {
	switch c {
	case ContextVaultAuth, ContextSession, ContextReceipt, ContextBoxKey, ContextRotate, ContextConnectCollect, ContextConnectReach:
		return true
	default:
		return false
	}
}

// spkiP256Prefix is the DER of a P-256 SubjectPublicKeyInfo up to its
// uncompressed point: id-ecPublicKey, prime256v1, a BIT STRING of 66 bytes.
var spkiP256Prefix = []byte{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
}

const (
	// spkiPrefixLen is len(spkiP256Prefix).
	spkiPrefixLen = 26
	// SPKILen is the only identity key encoding accepted: 91 bytes.
	SPKILen = spkiPrefixLen + PointLen
)

const (
	// engineIDBytes is how much of sha256(SPKI) makes an engine id.
	engineIDBytes = 16
	// fingerprintLen is how many characters of the id people compare.
	fingerprintLen = 16
	// fingerprintGroup is the size of each space-separated group.
	fingerprintGroup = 4
)

// ErrBadKey is a public key in any form but the 91-byte uncompressed P-256
// SPKI, or a point not on the curve.
var ErrBadKey = errors.New("vault channel: not a P-256 SPKI with an uncompressed point on the curve")

// ErrBadSignature is a signature that is not 64 bytes r || s or does not verify.
var ErrBadSignature = errors.New("vault channel: signature refused")

// spkiOfPoint wraps an uncompressed point in the fixed SPKI prefix.
func spkiOfPoint(point []byte) []byte { return concat(spkiP256Prefix, point) }

// ParseEngineKey reads a signing public key from its SPKI DER and refuses
// every other encoding (compressed point, explicit curve parameters, another
// curve, trailing bytes) and any point not on the curve.
func ParseEngineKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) != SPKILen || !bytes.HasPrefix(spki, spkiP256Prefix) {
		return nil, ErrBadKey
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), spki[spkiPrefixLen:])
	if err != nil {
		return nil, ErrBadKey
	}
	return pub, nil
}

// EngineIDOf is base64url of the first 16 bytes of sha256(spki): 22 characters.
func EngineIDOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return b64(sum[:engineIDBytes])
}

// FingerprintOf is what people compare: the engine id's first 16 characters
// in four groups of four, separated by spaces.
func FingerprintOf(engineID string) string {
	if len(engineID) < fingerprintLen {
		return engineID
	}
	groups := make([]string, 0, fingerprintLen/fingerprintGroup)
	for i := 0; i < fingerprintLen; i += fingerprintGroup {
		groups = append(groups, engineID[i:i+fingerprintGroup])
	}
	return strings.Join(groups, " ")
}

// VerifySignature checks a 64-byte r || s signature by pub over context
// followed by body. High-S signatures verify (WebCrypto makes either form).
func VerifySignature(pub *ecdsa.PublicKey, context SigningContext, body, sig []byte) error {
	if !context.valid() || len(sig) != SigLen {
		return ErrBadSignature
	}
	r := new(big.Int).SetBytes(sig[:SigLen/2])
	s := new(big.Int).SetBytes(sig[SigLen/2:])
	digest := sha256.Sum256(concat([]byte(context), body))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrBadSignature
	}
	return nil
}

// VerifyKeySignature is VerifySignature by the key whose SPKI DER is spki
// (ParseEngineKey's encoding; ErrBadKey for any other).
func VerifyKeySignature(spki []byte, context SigningContext, body, sig []byte) error {
	pub, err := ParseEngineKey(spki)
	if err != nil {
		return err
	}
	return VerifySignature(pub, context, body, sig)
}

// Signer signs under the engine's identity. EngineKeys is the one
// implementation outside tests.
type Signer interface {
	// PublicKeySPKI is the signing key's SPKI DER.
	PublicKeySPKI() []byte
	// Sign signs context followed by body and returns r || s.
	Sign(context SigningContext, body []byte) ([]byte, error)
}

// EngineKeys are the engine's two keys (CONTRACT.md, Vault channel, Engine
// keys): the ECDSA signing key, its identity, and the ECDH box key, kept for
// Phase 1b so the key file keeps its shape. Neither key does the other's job.
// An EngineKeys value never prints or logs a key.
type EngineKeys struct {
	signing   *ecdsa.PrivateKey
	box       *ecdh.PrivateKey
	spki      []byte
	engineID  string
	createdAt time.Time
	boxKeySig []byte
}

// GenerateEngineKeys makes a fresh signing key and box key, and signs the
// box key's public key with the signing key.
func GenerateEngineKeys(now func() time.Time) (*EngineKeys, error) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	box, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box key: %w", err)
	}
	k, err := newEngineKeys(signing, box, now().UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(ContextBoxKey, k.boxKeyStatement())
	if err != nil {
		return nil, err
	}
	k.boxKeySig = sig
	return k, nil
}

func newEngineKeys(signing *ecdsa.PrivateKey, box *ecdh.PrivateKey, createdAt time.Time) (*EngineKeys, error) {
	if signing.Curve != elliptic.P256() || box.Curve() != ecdh.P256() {
		return nil, errors.New("engine keys must be P-256")
	}
	point, err := signing.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	spki := spkiOfPoint(point)
	return &EngineKeys{signing: signing, box: box, spki: spki, engineID: EngineIDOf(spki), createdAt: createdAt}, nil
}

// boxKeyStatement is what boxKeySig signs after its context line:
// engineId + "\n" + box public key SPKI (base64url).
func (k *EngineKeys) boxKeyStatement() []byte {
	return []byte(k.engineID + "\n" + b64(k.BoxPublicKeySPKI()))
}

// EngineID is the engine's self-certifying id.
func (k *EngineKeys) EngineID() string { return k.engineID }

// Fingerprint is the id as people compare it.
func (k *EngineKeys) Fingerprint() string { return FingerprintOf(k.engineID) }

// CreatedAt is when these keys were made.
func (k *EngineKeys) CreatedAt() time.Time { return k.createdAt }

// PublicKeySPKI is a copy of the signing key's SPKI DER.
func (k *EngineKeys) PublicKeySPKI() []byte { return bytes.Clone(k.spki) }

// BoxPublicKeySPKI is a copy of the box key's public SPKI DER.
func (k *EngineKeys) BoxPublicKeySPKI() []byte { return spkiOfPoint(k.box.PublicKey().Bytes()) }

// Sign signs context followed by body with the signing key and returns the
// 64-byte r || s. Only the contract's contexts are signed.
func (k *EngineKeys) Sign(context SigningContext, body []byte) ([]byte, error) {
	if !context.valid() {
		return nil, fmt.Errorf("vault channel: %q is not a signing context", strings.TrimSuffix(string(context), "\n"))
	}
	digest := sha256.Sum256(concat([]byte(context), body))
	r, s, err := ecdsa.Sign(rand.Reader, k.signing, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig := make([]byte, SigLen)
	r.FillBytes(sig[:SigLen/2])
	s.FillBytes(sig[SigLen/2:])
	return sig, nil
}

// String names the engine, never a key.
func (k *EngineKeys) String() string { return "engine keys " + k.engineID }

// GoString names the engine, never a key.
func (k *EngineKeys) GoString() string { return k.String() }

// LogValue keeps keys out of structured logs.
func (k *EngineKeys) LogValue() slog.Value {
	return slog.GroupValue(slog.String("engineId", k.engineID))
}
