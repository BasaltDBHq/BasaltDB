package plugin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"regexp"
)

// ManifestSigContext is the context line a manifest signature covers before
// the manifest's exact bytes (CONTRACT.md, Plugins, Signing and the trust
// store). It keeps a manifest signature from being any other Basalt
// signature.
const ManifestSigContext = "basalt-plugin-manifest.1\n"

// SigAlg is the only signature algorithm: ECDSA P-256 with SHA-256.
const SigAlg = "ES256"

// Signature and key id sizes.
const (
	sigBytes    = 64 // r ‖ s, 32 bytes each
	keyIDBytes  = 16 // the first 16 bytes of sha256(SPKI DER)
	scalarBytes = 32
	// MaxSignatureFileBytes bounds a .sig file; a valid one is under 200 bytes.
	MaxSignatureFileBytes = 4 << 10
	// MaxKeyFileBytes bounds a key file; a P-256 PEM key is under 300 bytes.
	MaxKeyFileBytes = 16 << 10
)

// PEM block types of key files.
const (
	pemPublicKey  = "PUBLIC KEY"
	pemPrivateKey = "PRIVATE KEY"
)

var (
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	sigPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

// Key errors. They never carry a key's bytes.
var (
	errKeyNotOnePEM = errors.New("the key file must hold exactly one PEM block and nothing else")
	errKeyNotP256   = errors.New("the key is not a P-256 key")
	errKeyEncoding  = errors.New("the key is not a valid key of its PEM type")
)

// GenerateKey makes a new P-256 signing key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// KeyID is a public key's id: base64url, without padding, of the first 16
// bytes of sha256 of its DER SubjectPublicKeyInfo. It is always computed
// from the key, never read from a file name or label.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errKeyNotP256
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", errKeyEncoding
	}
	return keyIDOfDER(der), nil
}

func keyIDOfDER(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:keyIDBytes])
}

// MarshalPublicKey writes a public key file: PEM PUBLIC KEY
// (SubjectPublicKeyInfo).
func MarshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errKeyNotP256
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errKeyEncoding
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublicKey, Bytes: der}), nil
}

// MarshalPrivateKey writes a private key file: PEM PRIVATE KEY (PKCS#8).
// The caller writes it with mode 0600 and never prints it.
func MarshalPrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errKeyNotP256
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errKeyEncoding
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der}), nil
}

// ParsePublicKey reads a public key file: exactly one PEM PUBLIC KEY block
// holding a P-256 SubjectPublicKeyInfo in its canonical DER, with nothing
// but whitespace around it. It returns the key and its computed id. Errors
// never quote the file.
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, string, error) {
	block, err := onePEMBlock(b, pemPublicKey)
	if err != nil {
		return nil, "", err
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", errKeyEncoding
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errKeyNotP256
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !bytes.Equal(der, block.Bytes) {
		return nil, "", errKeyEncoding
	}
	return pub, keyIDOfDER(der), nil
}

// ParsePrivateKey reads a private key file: exactly one PEM PRIVATE KEY
// block holding a PKCS#8 P-256 key. Errors never quote the file.
func ParsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, err := onePEMBlock(b, pemPrivateKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errKeyEncoding
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errKeyNotP256
	}
	return priv, nil
}

// pemBegin starts a PEM block.
const pemBegin = "-----BEGIN "

// onePEMBlock is the single PEM block of type typ in b, with no headers and
// only whitespace before and after it. pem.Decode skips a malformed block
// before a good one, so the file must also hold exactly one BEGIN line.
func onePEMBlock(b []byte, typ string) (*pem.Block, error) {
	if len(b) > MaxKeyFileBytes || !bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte(pemBegin)) ||
		bytes.Count(b, []byte(pemBegin)) != 1 {
		return nil, errKeyNotOnePEM
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errKeyNotOnePEM
	}
	return block, nil
}

// signatureFile is basalt-plugin.json.sig (api/plugin/signature.schema.json).
type signatureFile struct {
	KeyID string `json:"keyId"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
}

// SignManifest signs a manifest's exact bytes and returns the contents of its
// basalt-plugin.json.sig. It does not check the manifest; the sign command
// does that first.
func SignManifest(manifest []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errKeyNotP256
	}
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	digest := manifestDigest(manifest)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, sigBytes)
	r.FillBytes(sig[:scalarBytes])
	s.FillBytes(sig[scalarBytes:])
	out, err := json.MarshalIndent(signatureFile{KeyID: id, Alg: SigAlg, Sig: base64.RawURLEncoding.EncodeToString(sig)}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func manifestDigest(manifest []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(ManifestSigContext))
	h.Write(manifest)
	var d [sha256.Size]byte
	h.Sum(d[:0])
	return d
}

// parseSignatureFile reads a .sig strictly: valid JSON with exactly the keys
// keyId, alg and sig, alg ES256, and keyId and sig in base64url without
// padding, decoded strictly (no padding, no other characters, no non-zero
// unused bits). It returns the key id and the 64-byte signature.
func parseSignatureFile(b []byte) (string, []byte, error) {
	bad := func(why string) error {
		return &VerifyError{Reason: RefusedNotTrusted, File: SignatureFile, Why: why}
	}
	if len(b) > MaxSignatureFileBytes {
		return "", nil, bad("the signature file is larger than 4 KiB")
	}
	if err := checkStrictJSON(b); err != nil {
		return "", nil, bad("the signature file is not valid JSON: " + err.Error())
	}
	obj, ok := objectOf(b)
	if !ok || len(obj) != 3 {
		return "", nil, bad("the signature file must be an object with exactly keyId, alg and sig")
	}
	var f signatureFile
	var okID, okAlg, okSig bool
	f.KeyID, okID = stringOf(obj["keyId"])
	f.Alg, okAlg = stringOf(obj["alg"])
	f.Sig, okSig = stringOf(obj["sig"])
	if !okID || !okAlg || !okSig {
		return "", nil, bad("the signature file must be an object with exactly keyId, alg and sig")
	}
	if f.Alg != SigAlg {
		return "", nil, bad("the signature's alg is not ES256")
	}
	if !keyIDPattern.MatchString(f.KeyID) {
		return "", nil, bad("the signature's keyId is not a key id")
	}
	if id, err := base64.RawURLEncoding.Strict().DecodeString(f.KeyID); err != nil || len(id) != keyIDBytes {
		return "", nil, bad("the signature's keyId is not strict base64url")
	}
	if !sigPattern.MatchString(f.Sig) {
		return "", nil, bad("the signature's sig is not 64 bytes of base64url")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(f.Sig)
	if err != nil || len(sig) != sigBytes {
		return "", nil, bad("the signature's sig is not strict base64url")
	}
	return f.KeyID, sig, nil
}

// verifyManifestSig checks an ES256 signature, r ‖ s, over the context line
// and the manifest's exact bytes. A high-S signature is accepted.
func verifyManifestSig(pub *ecdsa.PublicKey, manifest, sig []byte) bool {
	if pub == nil || len(sig) != sigBytes {
		return false
	}
	digest := manifestDigest(manifest)
	r := new(big.Int).SetBytes(sig[:scalarBytes])
	s := new(big.Int).SetBytes(sig[scalarBytes:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
