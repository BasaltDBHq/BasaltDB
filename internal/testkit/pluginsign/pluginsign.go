// Package pluginsign signs plugin manifests for tests, as a publisher's
// signing tool does (CONTRACT.md, Plugins, Signing and the trust store). The
// engine only verifies signatures; nothing in it signs one.
package pluginsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// manifestSigContext is the context line a manifest signature covers before
// the manifest's exact bytes.
const manifestSigContext = "basalt-plugin-manifest.1\n"

// Sizes of a signature and a key id.
const (
	sigBytes    = 64 // r ‖ s, 32 bytes each
	scalarBytes = 32
	keyIDBytes  = 16 // the first 16 bytes of sha256(SPKI DER)
)

var errNotP256 = errors.New("the key is not a P-256 key")

// GenerateKey makes a new P-256 signing key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// KeyID is a public key's id: base64url, without padding, of the first 16
// bytes of sha256 of its DER SubjectPublicKeyInfo.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errNotP256
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:keyIDBytes]), nil
}

// SignManifest signs a manifest's exact bytes and returns the contents of
// its basalt-plugin.json.sig (api/plugin/signature.schema.json).
func SignManifest(manifest []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errNotP256
	}
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(manifestSigContext), manifest...))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, sigBytes)
	r.FillBytes(sig[:scalarBytes])
	s.FillBytes(sig[scalarBytes:])
	out, err := json.MarshalIndent(struct {
		KeyID string `json:"keyId"`
		Alg   string `json:"alg"`
		Sig   string `json:"sig"`
	}{KeyID: id, Alg: "ES256", Sig: base64.RawURLEncoding.EncodeToString(sig)}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
