package vault_test

// The shared Vault channel vectors (CONTRACT.md, Vault channel, Test vectors):
// testdata/*.json in the format of vectors.schema.json. The Test*Vectors tests
// run every case through the reference in vaultref_test.go; web/lib/vault.test.mjs
// runs the same files with WebCrypto. Regenerate with
//
//	go test ./api/mcp/vault -run TestGenerateVaultVectors -update-vectors
//
// which seeds crypto randomness, so the same Go release writes the same bytes.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/stretchr/testify/require"
)

var updateVectors = flag.Bool("update-vectors", false, "rewrite api/mcp/vault/testdata from the reference")

const (
	refusedByPage   = "PAGE"
	refusedByEngine = "ENGINE"
	pageToEngine    = "PAGE_TO_ENGINE"
	engineToPage    = "ENGINE_TO_PAGE"
	vaultHost       = "relay.basaltvault.app"
	vectorSeed      = 20261112
)

type vectorFile[T any] struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Cases       []T    `json:"cases"`
}

type linkDerivationCase struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	LinkToken string `json:"linkToken"`
	PSK       string `json:"psk"`
}

type engineIDCase struct {
	Name        string `json:"name"`
	EngineKey   string `json:"engineKey"`
	EngineID    string `json:"engineId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Expect      string `json:"expect"`
}

type paddingCase struct {
	Name    string  `json:"name"`
	Content *string `json:"content,omitempty"`
	Padded  string  `json:"padded"`
	Expect  string  `json:"expect"`
}

type handshakeCase struct {
	Name                   string `json:"name"`
	Transport              string `json:"transport"`
	Secret                 string `json:"secret"`
	PageEphemeralPrivate   string `json:"pageEphemeralPrivate"`
	EngineEphemeralPrivate string `json:"engineEphemeralPrivate"`
	EngineSigningPrivate   string `json:"engineSigningPrivate"`
	EngineKey              string `json:"engineKey"`
	Prologue               string `json:"prologue"`
	Message1               string `json:"message1"`
	Sig                    string `json:"sig,omitempty"`
	Message2               string `json:"message2"`
	HandshakeHash          string `json:"handshakeHash,omitempty"`
	KeyPageToEngine        string `json:"keyPageToEngine,omitempty"`
	KeyEngineToPage        string `json:"keyEngineToPage,omitempty"`
	RefusedBy              string `json:"refusedBy,omitempty"`
	Expect                 string `json:"expect"`
}

type frameCase struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Key       string `json:"key"`
	Counter   uint64 `json:"counter"`
	Content   string `json:"content,omitempty"`
	Frame     string `json:"frame"`
	Expect    string `json:"expect"`
}

type signatureCase struct {
	Name      string `json:"name"`
	Context   string `json:"context"`
	PublicKey string `json:"publicKey"`
	Message   string `json:"message"`
	Sig       string `json:"sig"`
	Expect    string `json:"expect"`
}

type receiptCase struct {
	Name        string `json:"name"`
	Token       string `json:"token"`
	EngineKey   string `json:"engineKey"`
	PayloadJSON string `json:"payloadJson,omitempty"`
	Expect      string `json:"expect"`
}

const (
	fileLinkDerivation = "link-derivation.json"
	fileEngineID       = "engine-id.json"
	filePadding        = "padding.json"
	fileHandshake      = "handshake.json"
	fileFrame          = "frame.json"
	fileSignature      = "signature.json"
	fileReceipt        = "receipt.json"
)

func loadVectors[T any](t *testing.T, name, kind string) vectorFile[T] {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var f vectorFile[T]
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&f), name)
	require.Equal(t, kind, f.Kind, name)
	require.NotEmpty(t, f.Description, name)
	require.NotEmpty(t, f.Cases, name)
	return f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// --- Checks ---

func TestLinkDerivationVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[linkDerivationCase](t, fileLinkDerivation, "LINK_DERIVATION")
	for _, c := range f.Cases {
		lk, err := deriveLink(c.Secret)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.LinkToken, b64(lk.token), c.Name)
		require.Equal(t, c.PSK, hx(lk.psk), c.Name)
	}
}

func TestEngineIDVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[engineIDCase](t, fileEngineID, "ENGINE_ID")
	for _, c := range f.Cases {
		_, err := parseEngineKey(c.EngineKey)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		der, _ := unb64(c.EngineKey)
		require.Equal(t, c.EngineID, engineIDOf(der), c.Name)
		require.Equal(t, c.Fingerprint, fingerprintOf(c.EngineID), c.Name)
	}
}

func TestPaddingVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[paddingCase](t, filePadding, "PADDING")
	for _, c := range f.Cases {
		content, err := unpad(unhex(t, c.Padded))
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		require.NotNil(t, c.Content, c.Name)
		require.Equal(t, *c.Content, hx(content), c.Name)
		require.Equal(t, c.Padded, hx(pad(content)), c.Name)
	}
}

func welcomeJSON(engineKey, sig string) []byte {
	raw, err := json.Marshal(welcomePayload{EngineKey: engineKey, Sig: sig})
	if err != nil {
		panic(err)
	}
	return raw
}

func TestHandshakeVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[handshakeCase](t, fileHandshake, "HANDSHAKE")
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			checkHandshakeCase(t, c)
		})
	}
}

func checkHandshakeCase(t *testing.T, c handshakeCase) {
	t.Helper()
	lk, err := deriveLink(c.Secret)
	require.NoError(t, err)
	require.Equal(t, c.Prologue, hx(prologue(c.Transport, lk.token)))
	signer, err := signingKey(unhex(t, c.EngineSigningPrivate))
	require.NoError(t, err)
	require.Equal(t, c.EngineKey, b64(spkiOf(&signer.PublicKey)))
	pageE := ephemeral(unhex(t, c.PageEphemeralPrivate))
	message1 := unhex(t, c.Message1)

	if c.RefusedBy == refusedByEngine {
		_, _, err := engineReadMessage1(c.Transport, lk, message1)
		require.Equal(t, c.Expect, outcome(err))
		return
	}

	// The page is honest in every other case: it writes message 1 itself.
	written, pageState := writeMessage1(c.Transport, lk.token, lk.psk, pageE.PublicKey().Bytes())
	require.Equal(t, c.Message1, hx(written))

	if c.Expect == expectAccept {
		engineState, re, err := engineReadMessage1(c.Transport, lk, message1)
		require.NoError(t, err)
		message2, keys := writeMessage2(engineState, re, ephemeral(unhex(t, c.EngineEphemeralPrivate)), func([]byte) []byte {
			return welcomeJSON(c.EngineKey, c.Sig)
		})
		require.Equal(t, c.Message2, hx(message2))
		requireKeys(t, c, keys)
	}

	keys, err := pageReadMessage2(pageState, pageE, unhex(t, c.Message2))
	require.Equal(t, c.Expect, outcome(err))
	if err == nil {
		requireKeys(t, c, keys)
	}
}

// TestEngineChecksTagBeforePoint pins what the vectors cannot show: on
// message 1 the engine checks the tag before any point arithmetic, so a bad
// tag over an invalid point stops at the tag (both close with LINK_REFUSED).
func TestEngineChecksTagBeforePoint(t *testing.T) {
	t.Parallel()
	keys := newVectorKeys()
	lk := mustLink(keys.relaySecret)
	other := mustLink(keys.otherLink)
	pub := ephemeral(scalar("page ephemeral relay")).PublicKey().Bytes()

	run := func(m1 []byte) ([]string, error) {
		var steps []string
		_, _, err := readMessage1(transportRelay, lk, m1, func(step string) { steps = append(steps, step) })
		return steps, err
	}

	badTagBadPoint, _ := writeMessage1(transportRelay, lk.token, other.psk, offCurve(pub))
	steps, err := run(badTagBadPoint)
	require.ErrorIs(t, err, errLinkRefused)
	require.Equal(t, []string{"header", "token", "tag"}, steps)

	goodTagBadPoint, _ := writeMessage1(transportRelay, lk.token, lk.psk, offCurve(pub))
	steps, err = run(goodTagBadPoint)
	require.ErrorIs(t, err, errLinkRefused)
	require.Equal(t, []string{"header", "token", "tag", "point"}, steps)
}

func requireKeys(t *testing.T, c handshakeCase, keys sessionKeys) {
	t.Helper()
	require.Equal(t, c.HandshakeHash, hx(keys.h))
	require.Equal(t, c.KeyPageToEngine, hx(keys.pageToEngine))
	require.Equal(t, c.KeyEngineToPage, hx(keys.engineToPage))
}

func TestFrameVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[frameCase](t, fileFrame, "FRAME")
	for _, c := range f.Cases {
		frame := unhex(t, c.Frame)
		content, err := openFrame(unhex(t, c.Key), c.Counter, frame)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		require.Equal(t, c.Content, string(content), c.Name)
		require.Equal(t, c.Frame, hx(sealFrame(unhex(t, c.Key), c.Counter, pad([]byte(c.Content)))), c.Name)
	}
}

func TestSignatureVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[signatureCase](t, fileSignature, "SIGNATURE")
	seen := map[string]bool{}
	for _, c := range f.Cases {
		err := verifyContext(c.Context, c.PublicKey, unhex(t, c.Message), c.Sig)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err == nil {
			seen[c.Context] = true
		}
	}
	require.Len(t, seen, len(signingContexts), "every signing context has a valid vector")
}

func TestReceiptVectors(t *testing.T) {
	t.Parallel()
	f := loadVectors[receiptCase](t, fileReceipt, "RECEIPT")
	for _, c := range f.Cases {
		_, err := verifyReceipt(c.Token, c.EngineKey)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(c.Token, receiptPrefix), ".")
		payload, err := unb64(parts[0])
		require.NoError(t, err)
		require.Equal(t, c.PayloadJSON, string(payload), c.Name)
	}
}

// --- Generation ---

// scalar is a fixed P-256 private key for a vector, from its label.
func scalar(label string) []byte {
	sum := sha256.Sum256([]byte("basalt-vault-vectors " + label))
	return sum[:]
}

func secretOf(label string) string {
	sum := sha256.Sum256([]byte("basalt-vault-vectors secret " + label))
	return b64(sum[:secretLen])
}

func mustSigningKey(label string) *ecdsa.PrivateKey {
	k, err := signingKey(scalar(label))
	if err != nil {
		panic(err)
	}
	return k
}

func mustSign(key *ecdsa.PrivateKey, message []byte) string {
	sig, err := signRaw(key, message)
	if err != nil {
		panic(err)
	}
	return b64(sig)
}

func mustLink(secret string) linkKeys {
	lk, err := deriveLink(secret)
	if err != nil {
		panic(err)
	}
	return lk
}

// withHeader is msg with its two header bytes replaced.
func withHeader(msg []byte, version, typ byte) []byte {
	out := bytes.Clone(msg)
	out[0], out[1] = version, typ
	return out
}

// highS returns the form of an r||s signature whose s is above n/2 (s or
// n - s, both valid for the same message and key).
func highS(sig []byte) []byte {
	n := elliptic.P256().Params().N
	s := new(big.Int).SetBytes(sig[sigLen/2:])
	if s.Cmp(new(big.Int).Rsh(n, 1)) <= 0 {
		s.Sub(n, s)
	}
	out := bytes.Clone(sig)
	s.FillBytes(out[sigLen/2:])
	return out
}

func flipLast(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 1
	return out
}

// offCurve is a point with Y changed, so it is not on the curve.
func offCurve(point []byte) []byte { return flipLast(point) }

func writeVectors(t *testing.T, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", name), buf.Bytes(), 0o600))
}

type vectorKeys struct {
	engine, other, rotated *ecdsa.PrivateKey
	box, rotatedBox        *ecdh.PrivateKey
	relaySecret, otherLink string
}

func newVectorKeys() vectorKeys {
	return vectorKeys{
		engine:      mustSigningKey("engine signing key"),
		other:       mustSigningKey("other engine signing key"),
		rotated:     mustSigningKey("rotated engine signing key"),
		box:         ephemeral(scalar("engine box key")),
		rotatedBox:  ephemeral(scalar("rotated engine box key")),
		relaySecret: secretOf("relay link"),
		otherLink:   secretOf("another link"),
	}
}

func TestGenerateVaultVectors(t *testing.T) {
	if !*updateVectors {
		t.Skip("run with -update-vectors to rewrite testdata")
	}
	cryptotest.SetGlobalRandom(t, vectorSeed)
	require.NoError(t, os.MkdirAll("testdata", 0o750))
	keys := newVectorKeys()

	writeVectors(t, fileLinkDerivation, genLinkDerivation())
	writeVectors(t, fileEngineID, genEngineID(keys))
	writeVectors(t, filePadding, genPadding())
	handshakes, relay, direct := genHandshake(keys)
	writeVectors(t, fileHandshake, handshakes)
	writeVectors(t, fileFrame, genFrames(keys, relay, direct))
	writeVectors(t, fileSignature, genSignatures(keys, relay))
	writeVectors(t, fileReceipt, genReceipts(keys))
}

func genLinkDerivation() vectorFile[linkDerivationCase] {
	f := vectorFile[linkDerivationCase]{
		Kind:        "LINK_DERIVATION",
		Description: "linkToken = HKDF-SHA-256(secret, salt empty, info basalt-vault-link.1, 16 bytes) as base64url; psk = HKDF-SHA-256(secret, salt empty, info basalt-vault-psk.1, 32 bytes). The secret is the link's #s= value, 16 bytes in base64url.",
	}
	secrets := []struct{ name, secret string }{
		{"all-zero secret", b64(make([]byte, secretLen))},
		{"all-ones secret", b64(bytes.Repeat([]byte{0xff}, secretLen))},
		{"the contract's example secret", "q3Jv8sLk2mT0xYp1aBcD9w"},
		{"the handshake vectors' relay link", secretOf("relay link")},
	}
	for _, s := range secrets {
		lk := mustLink(s.secret)
		f.Cases = append(f.Cases, linkDerivationCase{Name: s.name, Secret: s.secret, LinkToken: b64(lk.token), PSK: hx(lk.psk)})
	}
	return f
}

// explicitParamsSPKI encodes a P-256 key with explicit curve parameters
// instead of the prime256v1 OID, which the contract refuses.
func explicitParamsSPKI(pub *ecdsa.PublicKey) []byte {
	type fieldID struct {
		FieldType asn1.ObjectIdentifier
		Prime     *big.Int
	}
	type curve struct{ A, B []byte }
	type ecParameters struct {
		Version  int
		FieldID  fieldID
		Curve    curve
		Base     []byte
		Order    *big.Int
		Cofactor int
	}
	type algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters ecParameters
	}
	type spki struct {
		Algorithm algorithm
		PublicKey asn1.BitString
	}
	p := elliptic.P256().Params()
	a := new(big.Int).Sub(p.P, big.NewInt(3))
	point, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	der, err := asn1.Marshal(spki{
		Algorithm: algorithm{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Parameters: ecParameters{
				Version: 1,
				FieldID: fieldID{FieldType: asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, Prime: p.P},
				Curve:   curve{A: a.FillBytes(make([]byte, scalarLen)), B: p.B.FillBytes(make([]byte, scalarLen))},
				Base: cat([]byte{0x04}, p.Gx.FillBytes(make([]byte, scalarLen)),
					p.Gy.FillBytes(make([]byte, scalarLen))),
				Order:    p.N,
				Cofactor: 1,
			},
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	if err != nil {
		panic(err)
	}
	return der
}

func compressedSPKI(pub *ecdsa.PublicKey) []byte {
	point, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), new(big.Int).SetBytes(point[1:33]), new(big.Int).SetBytes(point[33:]))
	return cat(mustHex("3039301306072a8648ce3d020106082a8648ce3d030107032200"), compressed)
}

func genEngineID(keys vectorKeys) vectorFile[engineIDCase] {
	f := vectorFile[engineIDCase]{
		Kind:        "ENGINE_ID",
		Description: "engineId = base64url of the first 16 bytes of sha256(signing key SPKI DER); fingerprint = its first 16 characters in four groups of four. Only the 91-byte SPKI with id-ecPublicKey, prime256v1 and an uncompressed point on the curve is accepted; every other encoding is refused.",
	}
	accept := func(name string, spki []byte) {
		id := engineIDOf(spki)
		f.Cases = append(f.Cases, engineIDCase{Name: name, EngineKey: b64(spki), EngineID: id, Fingerprint: fingerprintOf(id), Expect: expectAccept})
	}
	refuse := func(name string, der []byte) {
		f.Cases = append(f.Cases, engineIDCase{Name: name, EngineKey: b64(der), Expect: expectRefuse})
	}
	engineSPKI := spkiOf(&keys.engine.PublicKey)
	goSPKI, err := x509.MarshalPKIXPublicKey(&keys.engine.PublicKey)
	if err != nil || !bytes.Equal(goSPKI, engineSPKI) {
		panic("the SPKI prefix does not match crypto/x509")
	}
	accept("the vectors' engine signing key", engineSPKI)
	accept("another engine's signing key", spkiOf(&keys.other.PublicKey))
	refuse("a compressed point", compressedSPKI(&keys.engine.PublicKey))
	refuse("explicit curve parameters", explicitParamsSPKI(&keys.engine.PublicKey))
	refuse("a trailing byte", cat(engineSPKI, []byte{0}))
	refuse("a truncated key", engineSPKI[:len(engineSPKI)-1])
	refuse("a point off the curve", offCurve(engineSPKI))
	p384, err := ecdh.P384().NewPrivateKey(bytes.Repeat([]byte{0x11}, 48))
	if err != nil {
		panic(err)
	}
	p384SPKI, err := x509.MarshalPKIXPublicKey(p384.PublicKey())
	if err != nil {
		panic(err)
	}
	refuse("a P-384 key", p384SPKI)
	return f
}

func paddingPattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + i%26)
	}
	return out
}

func genPadding() vectorFile[paddingCase] {
	f := vectorFile[paddingCase]{
		Kind:        "PADDING",
		Description: "A frame's plaintext: len (4 bytes, big-endian) || content || zero bytes up to max(1024, the next power of two >= 4 + len), at most 32768. A receiver refuses (FRAME_INVALID) any other size for its len, a len past the end or over 32764, and a non-zero padding byte.",
	}
	accept := func(name string, content []byte) {
		s := hx(content)
		f.Cases = append(f.Cases, paddingCase{Name: name, Content: &s, Padded: hx(pad(content)), Expect: expectAccept})
	}
	refuse := func(name string, padded []byte) {
		f.Cases = append(f.Cases, paddingCase{Name: name, Padded: hx(padded), Expect: string(errFrameInvalid)})
	}
	accept("empty content fills the 1024 bucket", nil)
	accept("1020 bytes fill 1024 exactly", paddingPattern(padMin-lenPrefix))
	accept("1021 bytes move to 2048", paddingPattern(padMin-lenPrefix+1))
	accept("3000 bytes pad to 4096", paddingPattern(3000))
	accept("32764 bytes fill the largest bucket", paddingPattern(contentMax))

	nonZero := pad(paddingPattern(10))
	nonZero[len(nonZero)-1] = 1
	refuse("a non-zero padding byte", nonZero)

	tooBig := make([]byte, 2*padMin)
	binary.BigEndian.PutUint32(tooBig, 10)
	copy(tooBig[lenPrefix:], paddingPattern(10))
	refuse("10 bytes padded to 2048 instead of 1024", tooBig)

	notBucket := make([]byte, 1000)
	binary.BigEndian.PutUint32(notBucket, 10)
	refuse("a size that is not a bucket", notBucket)

	past := make([]byte, padMin)
	binary.BigEndian.PutUint32(past, 2000)
	refuse("len past the end", past)

	over := make([]byte, padMax)
	binary.BigEndian.PutUint32(over, contentMax+1)
	refuse("len over 32764", over)

	refuse("shorter than the length prefix", []byte{0, 0, 0})
	return f
}

type handshakeSetup struct {
	transport, secret string
	pageE, engineE    []byte
}

// handshakeBase fills the fields every case of one setup shares.
func handshakeBase(keys vectorKeys, s handshakeSetup) handshakeCase {
	lk := mustLink(s.secret)
	return handshakeCase{
		Transport:              s.transport,
		Secret:                 s.secret,
		PageEphemeralPrivate:   hx(s.pageE),
		EngineEphemeralPrivate: hx(s.engineE),
		EngineSigningPrivate:   hx(scalar("engine signing key")),
		EngineKey:              b64(spkiOf(&keys.engine.PublicKey)),
		Prologue:               hx(prologue(s.transport, lk.token)),
	}
}

func pagePub(s handshakeSetup) []byte { return ephemeral(s.pageE).PublicKey().Bytes() }

// genWelcome runs an honest page's message 1 into the engine and returns a
// message 2 whose payload the caller builds from h.
func genWelcome(s handshakeSetup, payload func(h []byte) []byte) ([]byte, sessionKeys, []byte) {
	lk := mustLink(s.secret)
	m1, _ := writeMessage1(s.transport, lk.token, lk.psk, pagePub(s))
	es, re, err := engineReadMessage1(s.transport, lk, m1)
	if err != nil {
		panic(err)
	}
	m2, keys := writeMessage2(es, re, ephemeral(s.engineE), payload)
	return m2, keys, m1
}

func genHandshake(keys vectorKeys) (f vectorFile[handshakeCase], relay, direct sessionKeys) {
	f = vectorFile[handshakeCase]{
		Kind:        "HANDSHAKE",
		Description: "Noise_NNpsk0_P256_AESGCM_SHA256 between the page (initiator) and the engine (responder), with the psk and linkToken from the link secret and the prologue basalt-vault-prologue.1\\n + transport + \\n + linkToken (base64url). In psk mode every e token is MixHash and MixKey of the 65-byte point. sig signs basalt-vault-session-sig.1\\n + h after e, ee; message 2's payload is the JSON {\"engineKey\",\"sig\"} in that order. refusedBy ENGINE: the engine reads message1 and closes; message2 is empty. refusedBy PAGE: the page writes message1 itself (it must match) and closes on message2. ACCEPT: both sides run, and the engine writes message2 with the pinned sig.",
	}
	engineKey := b64(spkiOf(&keys.engine.PublicKey))
	sessionLine := []byte(signingContexts["SESSION"])
	honest := func(h []byte) []byte {
		return welcomeJSON(engineKey, mustSign(keys.engine, cat(sessionLine, h)))
	}

	accept := func(name string, s handshakeSetup) sessionKeys {
		c := handshakeBase(keys, s)
		var sig string
		m2, sk, m1 := genWelcome(s, func(h []byte) []byte {
			sig = mustSign(keys.engine, cat(sessionLine, h))
			return welcomeJSON(engineKey, sig)
		})
		c.Name, c.Message1, c.Sig, c.Message2, c.Expect = name, hx(m1), sig, hx(m2), expectAccept
		c.HandshakeHash, c.KeyPageToEngine, c.KeyEngineToPage = hx(sk.h), hx(sk.pageToEngine), hx(sk.engineToPage)
		f.Cases = append(f.Cases, c)
		return sk
	}
	relaySetup := handshakeSetup{transportRelay, keys.relaySecret, scalar("page ephemeral relay"), scalar("engine ephemeral relay")}
	directSetup := handshakeSetup{transportDirect, secretOf("direct link"), scalar("page ephemeral direct"), scalar("engine ephemeral direct")}
	relay = accept("a relay session", relaySetup)
	direct = accept("a direct session", directSetup)

	lk := mustLink(keys.relaySecret)
	other := mustLink(keys.otherLink)
	goodM2, _, goodM1 := genWelcome(relaySetup, honest)

	engineRefuses := func(name string, m1 []byte, expect vaultCloseError) {
		c := handshakeBase(keys, relaySetup)
		c.Name, c.Message1, c.RefusedBy, c.Expect = name, hx(m1), refusedByEngine, string(expect)
		f.Cases = append(f.Cases, c)
	}
	wrongPSK, _ := writeMessage1(transportRelay, lk.token, other.psk, pagePub(relaySetup))
	engineRefuses("message 1 under a wrong psk", wrongPSK, errLinkRefused)
	wrongToken, _ := writeMessage1(transportRelay, other.token, other.psk, pagePub(relaySetup))
	engineRefuses("message 1 for a token the engine does not hold", wrongToken, errLinkRefused)
	engineRefuses("a tampered tag", flipLast(goodM1), errLinkRefused)
	badPoint, _ := writeMessage1(transportRelay, lk.token, lk.psk, offCurve(pagePub(relaySetup)))
	engineRefuses("a valid tag over a point off the curve", badPoint, errLinkRefused)
	compressed := pagePub(relaySetup)
	compressed[0] = 0x02
	compressedM1, _ := writeMessage1(transportRelay, lk.token, lk.psk, compressed)
	engineRefuses("a valid tag over a compressed-point prefix", compressedM1, errLinkRefused)
	otherTransport, _ := writeMessage1(transportDirect, lk.token, lk.psk, pagePub(relaySetup))
	engineRefuses("message 1 made for the direct transport", otherTransport, errLinkRefused)
	version := bytes.Clone(goodM1)
	version[0] = 0x02
	engineRefuses("version 2", version, errVersion)
	engineRefuses("98 bytes", goodM1[:message1Len-1], errProtocol)
	engineRefuses("message 2 reflected to the engine", goodM2, errProtocol)

	pageRefuses := func(name string, m2 []byte, expect vaultCloseError) {
		c := handshakeBase(keys, relaySetup)
		c.Name, c.Message1, c.Message2, c.RefusedBy, c.Expect = name, hx(goodM1), hx(m2), refusedByPage, string(expect)
		f.Cases = append(f.Cases, c)
	}
	welcome := func(payload func(h []byte) []byte) []byte {
		m2, _, _ := genWelcome(relaySetup, payload)
		return m2
	}
	badE := bytes.Clone(goodM2)
	badE[headerLen+pointLen-1] ^= 1
	pageRefuses("an engine ephemeral key off the curve", badE, errHandshakeFailed)
	pageRefuses("a tampered ciphertext", flipLast(goodM2), errHandshakeFailed)
	pageRefuses("signed by another key", welcome(func(h []byte) []byte {
		return welcomeJSON(engineKey, mustSign(keys.other, cat(sessionLine, h)))
	}), errHandshakeFailed)
	pageRefuses("signed under the receipt context", welcome(func(h []byte) []byte {
		return welcomeJSON(engineKey, mustSign(keys.engine, cat([]byte(signingContexts["RECEIPT"]), h)))
	}), errHandshakeFailed)
	pageRefuses("an engine key in compressed form", welcome(func(h []byte) []byte {
		return welcomeJSON(b64(compressedSPKI(&keys.engine.PublicKey)), mustSign(keys.engine, cat(sessionLine, h)))
	}), errHandshakeFailed)
	pageRefuses("a payload with an unknown field", welcome(func(h []byte) []byte {
		return []byte(fmt.Sprintf(`{"engineKey":%q,"sig":%q,"extra":true}`, engineKey, mustSign(keys.engine, cat(sessionLine, h))))
	}), errHandshakeFailed)
	pageRefuses("message 2 from an engine with another psk", func() []byte {
		_, es := writeMessage1(transportRelay, lk.token, other.psk, pagePub(relaySetup))
		re, err := ecdh.P256().NewPublicKey(pagePub(relaySetup))
		if err != nil {
			panic(err)
		}
		m2, _ := writeMessage2(es, re, ephemeral(relaySetup.engineE), honest)
		return m2
	}(), errHandshakeFailed)
	pageRefuses("message 1 reflected to the page", goodM1, errProtocol)
	version2 := bytes.Clone(goodM2)
	version2[0] = 0x02
	pageRefuses("version 2", version2, errVersion)
	oversize := welcome(func(h []byte) []byte {
		return []byte(fmt.Sprintf(`{"engineKey":%q,"sig":%q,"pad":%q}`, engineKey,
			mustSign(keys.engine, cat(sessionLine, h)), strings.Repeat("x", message2Max)))
	})
	pageRefuses("over 1024 bytes", oversize, errTooLarge)

	// Two faults in one message pin the order of the checks.
	engineRefuses("version 2 at 98 bytes: the version comes first", withHeader(goodM1[:message1Len-1], 0x02, typeHello), errVersion)
	engineRefuses("version 2 with the WELCOME type: the version comes first", withHeader(goodM1, 0x02, typeWelcome), errVersion)
	engineRefuses("the WELCOME type at 98 bytes", withHeader(goodM1[:message1Len-1], wireVersion, typeWelcome), errProtocol)
	pageRefuses("version 2 over 1024 bytes: the version comes before the size", withHeader(oversize, 0x02, typeWelcome), errVersion)
	pageRefuses("the HELLO type over 1024 bytes: the type comes before the size", withHeader(oversize, wireVersion, typeHello), errProtocol)
	pageRefuses("over 1024 bytes with an engine key off the curve: the size comes first", func() []byte {
		m := bytes.Clone(oversize)
		m[headerLen+pointLen-1] ^= 1
		return m
	}(), errTooLarge)
	return f, relay, direct
}

const vectorItemID = "0192f3a0-7c1e-7b2a-9c4d-5e6f708192a3"

func requestJSON(id int, method, path, body string, secret string) string {
	headers := fmt.Sprintf(`{"basalt-link-secret":%q,"origin":"https://portal.basaltvault.app"}`, secret)
	if method == "POST" {
		headers = fmt.Sprintf(`{"basalt-link-secret":%q,"content-type":"application/json","origin":"https://portal.basaltvault.app"}`, secret)
	}
	return fmt.Sprintf(`{"type":"REQUEST","id":%d,"method":%q,"path":%q,"headers":%s,"body":%q,"more":false}`, id, method, path, headers, body)
}

func responseJSON(id int, body string, more bool) string {
	return fmt.Sprintf(`{"type":"RESPONSE","id":%d,"status":200,"headers":{"content-type":"application/json"},"body":%q,"more":%t}`, id, body, more)
}

func genFrames(keys vectorKeys, relay, direct sessionKeys) vectorFile[frameCase] {
	f := vectorFile[frameCase]{
		Kind:        "FRAME",
		Description: "Frames of the relay session in handshake.json (and one of its direct session): 0x01 0x03 || AES-256-GCM(key, nonce 4 zero bytes || counter big-endian, ad the 2 header bytes, padded plaintext). key and counter are the receiver's own. A receiver checks the size (TOO_LARGE over 32786), the version (UNSUPPORTED_VERSION), the type (PROTOCOL), then decrypts and unpads (FRAME_INVALID).",
	}
	add := func(name, dir string, key []byte, counter uint64, content string, frame []byte, expect string) {
		f.Cases = append(f.Cases, frameCase{Name: name, Direction: dir, Key: hx(key), Counter: counter, Content: content, Frame: hx(frame), Expect: expect})
	}
	accept := func(name, dir string, key []byte, counter uint64, content string) []byte {
		frame := sealFrame(key, counter, pad([]byte(content)))
		add(name, dir, key, counter, content, frame, expectAccept)
		return frame
	}
	refuse := func(name, dir string, key []byte, counter uint64, frame []byte, expect vaultCloseError) {
		add(name, dir, key, counter, "", frame, string(expect))
	}
	k1, k2 := relay.pageToEngine, relay.engineToPage
	path := "/api/v1/approvals/" + vectorItemID
	getReq := requestJSON(1, "GET", path, "", keys.relaySecret)
	first := accept("the first request", pageToEngine, k1, 0, getReq)
	firstResp := accept("its response", engineToPage, k2, 0, responseJSON(1, `{"approvalId":"`+vectorItemID+`","status":"PENDING"}`, false))
	accept("a POST, the second request", pageToEngine, k1, 1, requestJSON(2, "POST", path+"/approve", `{"signature":"`+strings.Repeat("A", 86)+`"}`, keys.relaySecret))
	accept("a response padded to 2048", engineToPage, k2, 1, responseJSON(2, strings.Repeat("r", 1500), false))

	// A response that fills one frame exactly (32764 bytes of content, a
	// 32786-byte frame), then its continuation.
	empty := len(responseJSON(3, "", true))
	full := responseJSON(3, strings.Repeat("b", contentMax-empty), true)
	largest := accept("a response that fills the largest frame", engineToPage, k2, 2, full)
	accept("its continuation", engineToPage, k2, 3, `{"type":"CONTINUE","id":3,"body":"end","more":false}`)

	second := sealFrame(k1, 1, pad([]byte(requestJSON(2, "GET", path, "", keys.relaySecret))))
	refuse("reordered: the second frame first", pageToEngine, k1, 0, second, errFrameInvalid)
	refuse("replayed: the first frame again", pageToEngine, k1, 1, first, errFrameInvalid)
	refuse("reflected: the engine's frame sent back to it", pageToEngine, k1, 0, firstResp, errFrameInvalid)
	spliced := sealFrame(direct.pageToEngine, 0, pad([]byte(getReq)))
	refuse("spliced: a frame from another session", pageToEngine, k1, 0, spliced, errFrameInvalid)
	refuse("a tampered tag", pageToEngine, k1, 0, flipLast(first), errFrameInvalid)
	tampered := bytes.Clone(first)
	tampered[headerLen] ^= 1
	refuse("a tampered ciphertext", pageToEngine, k1, 0, tampered, errFrameInvalid)
	refuse("a truncated frame", pageToEngine, k1, 0, first[:len(first)-1], errFrameInvalid)
	nonZero := pad([]byte(getReq))
	nonZero[len(nonZero)-1] = 1
	refuse("a non-zero padding byte", pageToEngine, k1, 0, sealFrame(k1, 0, nonZero), errFrameInvalid)
	wide := make([]byte, 2*padMin)
	binary.BigEndian.PutUint32(wide, uint32(len(getReq)))
	copy(wide[lenPrefix:], getReq)
	refuse("a small request padded to 2048", pageToEngine, k1, 0, sealFrame(k1, 0, wide), errFrameInvalid)
	version := bytes.Clone(first)
	version[0] = 0x02
	refuse("version 2", pageToEngine, k1, 0, version, errVersion)
	hello := bytes.Clone(first)
	hello[1] = typeHello
	refuse("a HELLO type after the handshake", pageToEngine, k1, 0, hello, errProtocol)
	refuse("one byte over the largest frame", engineToPage, k2, 2, cat(largest, []byte{0}), errTooLarge)

	// Two faults in one frame pin the order: size, version, type, then decrypt.
	refuse("version 2 on an oversize frame: the size comes first", engineToPage, k2, 2, withHeader(cat(largest, []byte{0}), 0x02, typeFrame), errTooLarge)
	refuse("the HELLO type on an oversize frame: the size comes first", engineToPage, k2, 2, withHeader(cat(largest, []byte{0}), wireVersion, typeHello), errTooLarge)
	refuse("version 2 with the HELLO type: the version comes before the type", pageToEngine, k1, 0, withHeader(first, 0x02, typeHello), errVersion)
	refuse("the HELLO type on a frame that does not decrypt: the type comes first", pageToEngine, k1, 0, withHeader(flipLast(first), wireVersion, typeHello), errProtocol)
	return f
}

func genSignatures(keys vectorKeys, relay sessionKeys) vectorFile[signatureCase] {
	f := vectorFile[signatureCase]{
		Kind:        "SIGNATURE",
		Description: "ECDSA P-256 SHA-256 signatures, 64 bytes r||s in base64url, by the engine signing key, each over its context line and the bytes that follow (CONTRACT.md, Primitives and encodings). A verifier for a context refuses a message that does not start with its line, a signature made under another context, any other key, and any other length.",
	}
	engineKey := b64(spkiOf(&keys.engine.PublicKey))
	engineID := engineIDOf(spkiOf(&keys.engine.PublicKey))
	boxSPKI := b64(cat(spkiP256Prefix, keys.box.PublicKey().Bytes()))
	challengeSum := sha256.Sum256([]byte("challenge"))
	challenge := b64(challengeSum[:])
	at := "2026-11-12T09:30:00Z"
	bodies := []struct{ context, body string }{
		{"VAULT_AUTH", challenge + "\n" + vaultHost},
		{"SESSION", string(relay.h)},
		{"RECEIPT", `{"format":1}`},
		{"BOX_KEY", engineID + "\n" + boxSPKI},
		{"ROTATE", engineID + "\n" + b64(spkiOf(&keys.rotated.PublicKey)) + "\n" +
			b64(cat(spkiP256Prefix, keys.rotatedBox.PublicKey().Bytes())) + "\n" + at},
	}
	add := func(name, context, publicKey string, message []byte, sig, expect string) {
		f.Cases = append(f.Cases, signatureCase{Name: name, Context: context, PublicKey: publicKey, Message: hx(message), Sig: sig, Expect: expect})
	}
	for _, b := range bodies {
		message := []byte(signingContexts[b.context] + b.body)
		add(strings.ToLower(b.context)+": valid", b.context, engineKey, message, mustSign(keys.engine, message), expectAccept)
	}
	receipt := []byte(signingContexts["RECEIPT"] + `{"format":1}`)
	session := []byte(signingContexts["SESSION"] + `{"format":1}`)
	add("a session signature over the same bytes, checked as a receipt", "RECEIPT", engineKey, receipt, mustSign(keys.engine, session), expectRefuse)
	add("a message under another context line", "RECEIPT", engineKey, session, mustSign(keys.engine, session), expectRefuse)
	add("another engine's key", "RECEIPT", engineKey, receipt, mustSign(keys.other, receipt), expectRefuse)
	add("a signature over other bytes", "RECEIPT", engineKey, receipt, mustSign(keys.engine, cat(receipt, []byte(" "))), expectRefuse)
	sig, err := signRaw(keys.engine, receipt)
	if err != nil {
		panic(err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	if err != nil {
		panic(err)
	}
	add("an ASN.1 DER signature", "RECEIPT", engineKey, receipt, b64(der), expectRefuse)
	add("a zero signature", "RECEIPT", engineKey, receipt, b64(make([]byte, sigLen)), expectRefuse)
	add("a high-S signature is accepted", "RECEIPT", engineKey, receipt, b64(highS(sig)), expectAccept)
	return f
}

func receiptToken(key *ecdsa.PrivateKey, payload []byte, context string) string {
	return receiptPrefix + b64(payload) + "." + mustSign(key, cat([]byte(signingContexts[context]), payload))
}

func genReceipts(keys vectorKeys) vectorFile[receiptCase] {
	f := vectorFile[receiptCase]{
		Kind:        "RECEIPT",
		Description: "Receipt tokens basalt-receipt.1.<payload>.<sig>, checked against engineKey, the key the verifier expects from outside the receipt: the signature over basalt-receipt.1\\n + the payload bytes, then that engineId is that key's id, then the closed receipt.schema.json.",
	}
	engineKey := b64(spkiOf(&keys.engine.PublicKey))
	engineID := engineIDOf(spkiOf(&keys.engine.PublicKey))
	otherID := engineIDOf(spkiOf(&keys.other.PublicKey))
	rowsSum := sha256.Sum256([]byte("rows"))
	rowsHash := hx(rowsSum[:])
	changeID := "0192f3a0-7d00-7000-8000-000000000001"
	payload := func(kind, status, id, extra string) []byte {
		return []byte(fmt.Sprintf(`{"format":1,"kind":%q,"itemId":%q,"status":%q,"headline":"Update 3 rows in public.orders","rowsHash":%q,"agent":"billing-bot","engineId":%q,"at":"2026-11-12T09:30:00Z"%s}`,
			kind, vectorItemID, status, rowsHash, id, extra))
	}
	add := func(name, token string, payloadJSON []byte, expect string) {
		f.Cases = append(f.Cases, receiptCase{Name: name, Token: token, EngineKey: engineKey, PayloadJSON: string(payloadJSON), Expect: expect})
	}
	refuse := func(name, token string) { add(name, token, nil, expectRefuse) }

	approval := payload("APPROVAL", "APPROVED", engineID, "")
	add("an approval", receiptToken(keys.engine, approval, "RECEIPT"), approval, expectAccept)
	revert := payload("REVERT", "APPLIED", engineID, fmt.Sprintf(`,"changeId":%q`, changeID))
	add("a revert with its change", receiptToken(keys.engine, revert, "RECEIPT"), revert, expectAccept)

	refuse("signed by another engine, with its own id", receiptToken(keys.other, payload("APPROVAL", "APPROVED", otherID, ""), "RECEIPT"))
	refuse("signed by another engine, claiming the expected id", receiptToken(keys.other, approval, "RECEIPT"))
	refuse("signed by the expected key, naming another engine", receiptToken(keys.engine, payload("APPROVAL", "APPROVED", otherID, ""), "RECEIPT"))
	altered := []byte(strings.Replace(string(approval), rowsHash, strings.Repeat("0", 64), 1))
	sig := receiptToken(keys.engine, approval, "RECEIPT")
	refuse("rowsHash changed after signing", receiptPrefix+b64(altered)+sig[strings.LastIndex(sig, "."):])
	refuse("signed under the session context", receiptToken(keys.engine, approval, "SESSION"))
	missing := []byte(strings.Replace(string(approval), `"rowsHash":"`+rowsHash+`",`, "", 1))
	refuse("validly signed without rowsHash", receiptToken(keys.engine, missing, "RECEIPT"))
	refuse("validly signed with an unknown field", receiptToken(keys.engine, payload("APPROVAL", "APPROVED", engineID, `,"rows":3`), "RECEIPT"))
	refuse("validly signed with format 2", receiptToken(keys.engine, []byte(strings.Replace(string(approval), `"format":1`, `"format":2`, 1)), "RECEIPT"))
	return f
}
