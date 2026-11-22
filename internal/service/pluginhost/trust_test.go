package pluginhost

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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestKeysRoundTrip: a generated key's files parse back to the same key, and
// its id is computed from the key.
func TestKeysRoundTrip(t *testing.T) {
	t.Parallel()
	priv, err := GenerateKey()
	require.NoError(t, err)
	pubPEM, err := MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	privPEM, err := MarshalPrivateKey(priv)
	require.NoError(t, err)

	pub, id, err := ParsePublicKey(pubPEM)
	require.NoError(t, err)
	require.True(t, pub.Equal(&priv.PublicKey))
	want, err := KeyID(&priv.PublicKey)
	require.NoError(t, err)
	require.Equal(t, want, id)
	require.Len(t, id, 22)

	back, err := ParsePrivateKey(privPEM)
	require.NoError(t, err)
	require.True(t, back.Equal(priv))

	_, _, err = ParsePublicKey(privPEM)
	require.Error(t, err, "a private key is not a public key file")
	_, err = ParsePrivateKey(pubPEM)
	require.Error(t, err)
}

// TestSignatureVectorKeyID: the contract vector's key id is the one computed
// from its key.
func TestSignatureVectorKeyID(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join(contractTestdata, "signed", "publisher.pub"))
	require.NoError(t, err)
	_, id, err := ParsePublicKey(b)
	require.NoError(t, err)
	require.Equal(t, "jNZPxNG5htlwfhg4ZgknAA", id)
}

// TestParsePublicKeyStrict: anything but exactly one PEM PUBLIC KEY with a
// P-256 key in canonical DER is refused, and the error quotes nothing.
func TestParsePublicKeyStrict(t *testing.T) {
	t.Parallel()
	priv, err := GenerateKey()
	require.NoError(t, err)
	good, err := MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der384, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(good)
	withHeader := pem.EncodeToMemory(&pem.Block{Type: pemPublicKey, Headers: map[string]string{"Comment": "x"}, Bytes: block.Bytes})

	for name, b := range map[string][]byte{
		"two keys":       append(append([]byte{}, good...), good...),
		"leading text":   append([]byte("note\n"), good...),
		"trailing text":  append(append([]byte{}, good...), []byte("note\n")...),
		"P-384":          pem.EncodeToMemory(&pem.Block{Type: pemPublicKey, Bytes: der384}),
		"wrong type":     pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: block.Bytes}),
		"headers":        withHeader,
		"trailing bytes": pem.EncodeToMemory(&pem.Block{Type: pemPublicKey, Bytes: append(append([]byte{}, block.Bytes...), 0)}),
		"empty":          nil,
		"broken first":   append([]byte("-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----\n"), good...),
	} {
		_, _, err := ParsePublicKey(b)
		require.Error(t, err, name)
		require.NotContains(t, err.Error(), "MFkw", name)
	}
	_, _, err = ParsePublicKey(append([]byte("\n\n"), append(append([]byte{}, good...), "\n "...)...))
	require.NoError(t, err, "whitespace around the block is allowed")
}

// TestTrustAdd: a key is stored as <its computed id>.pem; adding it again
// changes nothing.
func TestTrustAdd(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	priv, err := GenerateKey()
	require.NoError(t, err)
	pemBytes, err := MarshalPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	id, added, err := f.trust.Add(append([]byte("\n"), pemBytes...))
	require.NoError(t, err)
	require.True(t, added)
	path := filepath.Join(f.trust.Dir(), id+trustFileExt)
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, pemBytes, stored, "the canonical PEM is stored")

	again, added, err := f.trust.Add(pemBytes)
	require.NoError(t, err)
	require.False(t, added)
	require.Equal(t, id, again)

	_, _, err = f.trust.Add([]byte("not a key"))
	require.Error(t, err)
}

// TestTrustStoreKeyFiles: a key file whose name is not its key's id, or that
// holds anything but one P-256 key, is not trusted; a key file that is a
// symlink fails the path rule.
func TestTrustStoreKeyFiles(t *testing.T) {
	t.Parallel()

	// The signer's key stored under another key's id: the signature names
	// that id, the file holds a key with a different one.
	f := newFixture(t)
	signerID, err := KeyID(&f.signer.PublicKey)
	require.NoError(t, err)
	impostor, err := GenerateKey()
	require.NoError(t, err)
	impostorPEM, err := MarshalPublicKey(&impostor.PublicKey)
	require.NoError(t, err)
	keyFile := filepath.Join(f.trust.Dir(), signerID+trustFileExt)
	require.NoError(t, os.WriteFile(keyFile, impostorPEM, 0o644))
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	ve := requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, keyFile, ve.File)
	require.Contains(t, ve.Why, "name is not the id")

	// Two keys in one file.
	signerPEM, err := MarshalPublicKey(&f.signer.PublicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, append(append([]byte{}, signerPEM...), impostorPEM...), 0o644))
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	ve = requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, keyFile, ve.File)
	requireNoSecrets(t, err)

	// A key file that is a symlink to a good key.
	elsewhere := filepath.Join(f.base, "key.pem")
	require.NoError(t, os.WriteFile(elsewhere, signerPEM, 0o644))
	require.NoError(t, os.Remove(keyFile))
	require.NoError(t, os.Symlink(elsewhere, keyFile))
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	ve = requireRefused(t, err, RefusedNotTrusted)
	require.Equal(t, keyFile, ve.File)
	require.Contains(t, ve.Why, "symlink")

	// Back to the real key: it verifies again.
	require.NoError(t, os.Remove(keyFile))
	require.NoError(t, os.WriteFile(keyFile, signerPEM, 0o644))
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
}

// TestEmbeddedKeys: a built-in publisher key is trusted by its computed id
// with no file in plugin-trust/. No key is built in yet.
func TestEmbeddedKeys(t *testing.T) {
	t.Parallel()
	keys, err := embeddedKeys()
	require.NoError(t, err)
	require.Empty(t, keys, "the publisher key is added when it is generated")

	f := newFixture(t)
	publisher, err := GenerateKey()
	require.NoError(t, err)
	id, err := KeyID(&publisher.PublicKey)
	require.NoError(t, err)
	trust := f.trust
	trust.embedded = map[string]*ecdsa.PublicKey{id: &publisher.PublicKey}
	f.writeSigned(f.src, localManifest(), publisher)
	v, err := Install(f.src, f.root, "", trust, ModeSameUser)
	require.NoError(t, err)
	require.Equal(t, id, v.SignerKeyID)
	_, err = Verify(f.root, EntryKey{Name: "acme-ner", Instance: DefaultInstance}, v.ManifestSHA256, f.trust, ModeSameUser)
	requireRefused(t, err, RefusedNotTrusted)
}

// TestSignatureFileStrict: the .sig is decoded strictly: padding, a newline,
// non-zero unused bits, an unknown or missing field, another alg, a DER
// signature and a key id in another case are refused.
func TestSignatureFileStrict(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	raw, err := os.ReadFile(filepath.Join(f.src, SignatureFile))
	require.NoError(t, err)
	var sig signatureFile
	require.NoError(t, json.Unmarshal(raw, &sig))

	encode := func(s signatureFile, extra string) []byte {
		b, err := json.Marshal(s)
		require.NoError(t, err)
		if extra != "" {
			b = append(b[:len(b)-1], []byte(","+extra+"}")...)
		}
		return b
	}
	mutate := func(fn func(*signatureFile)) []byte {
		s := sig
		fn(&s)
		return encode(s, "")
	}
	// The last character of sig and of keyId each carry 4 unused bits.
	flipLow := func(s string) string {
		last := strings.IndexByte(base64Alphabet, s[len(s)-1])
		return s[:len(s)-1] + string(base64Alphabet[last^1])
	}
	cases := map[string][]byte{
		"padding":           mutate(func(s *signatureFile) { s.Sig += "==" }),
		"newline":           mutate(func(s *signatureFile) { s.Sig = s.Sig[:40] + "\n" + s.Sig[40:] }),
		"sig unused bits":   mutate(func(s *signatureFile) { s.Sig = flipLow(s.Sig) }),
		"keyId unused bits": mutate(func(s *signatureFile) { s.KeyID = flipLow(s.KeyID) }),
		"keyId other case":  mutate(func(s *signatureFile) { s.KeyID = swapCase(s.KeyID) }),
		"alg":               mutate(func(s *signatureFile) { s.Alg = "ES384" }),
		"std base64":        mutate(func(s *signatureFile) { s.Sig = "+" + s.Sig[1:] }),
		"short":             mutate(func(s *signatureFile) { s.Sig = s.Sig[:84] }),
		"unknown field":     encode(sig, `"note":"x"`),
		"repeated field":    encode(sig, `"alg":"ES256"`),
		"missing field":     []byte(`{"keyId":"` + sig.KeyID + `","alg":"ES256"}`),
		"keyId path":        mutate(func(s *signatureFile) { s.KeyID = "../../../../../etc/pass" }),
		"not json":          []byte("sig"),
	}
	for name, b := range cases {
		if bytes.Equal(b, raw) {
			t.Fatalf("%s: the case did not change the signature", name)
		}
		require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), b, 0o644))
		_, err := Install(f.src, f.root, "", f.trust, ModeSameUser)
		require.Error(t, err, name)
		requireRefused(t, err, RefusedNotTrusted)
	}
	require.NoError(t, os.WriteFile(filepath.Join(f.src, SignatureFile), raw, 0o644))
	_, err = Install(f.src, f.root, "", f.trust, ModeSameUser)
	require.NoError(t, err)
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// swapCase changes the case of the first letter, so the id differs only in
// case.
func swapCase(s string) string {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			return s[:i] + strings.ToUpper(string(c)) + s[i+1:]
		case c >= 'A' && c <= 'Z':
			return s[:i] + strings.ToLower(string(c)) + s[i+1:]
		}
	}
	return s
}

// TestSignVerifiesContextLine: the signature covers the context line and
// the exact bytes; a signature of the bare manifest does not verify.
func TestSignVerifiesContextLine(t *testing.T) {
	t.Parallel()
	priv, err := GenerateKey()
	require.NoError(t, err)
	m := localManifest()
	raw, err := SignManifest(m, priv)
	require.NoError(t, err)
	_, sig, err := parseSignatureFile(raw)
	require.NoError(t, err)
	require.True(t, verifyManifestSig(&priv.PublicKey, m, sig))
	require.False(t, verifyManifestSig(&priv.PublicKey, append(append([]byte{}, m...), ' '), sig))
	require.False(t, verifyManifestSig(&priv.PublicKey, append([]byte(ManifestSigContext), m...), sig))

	other, err := GenerateKey()
	require.NoError(t, err)
	require.False(t, verifyManifestSig(&other.PublicKey, m, sig))

	// A signature over the bare manifest, without the context line, fails.
	bare := sha256.Sum256(m)
	r, s, err := ecdsa.Sign(rand.Reader, priv, bare[:])
	require.NoError(t, err)
	bareSig := make([]byte, sigBytes)
	r.FillBytes(bareSig[:scalarBytes])
	s.FillBytes(bareSig[scalarBytes:])
	require.True(t, ecdsa.Verify(&priv.PublicKey, bare[:], r, s))
	require.False(t, verifyManifestSig(&priv.PublicKey, m, bareSig))
	require.Len(t, base64.RawURLEncoding.EncodeToString(sig), 86)
}
