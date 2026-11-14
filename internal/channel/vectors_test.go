package channel

// The shared Vault channel vectors (api/mcp/vault/testdata, CONTRACT.md,
// Vault channel, Test vectors) run through this package: every byte the
// engine writes must match, and every refusal must close with the pinned code.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	vectorsDir      = "../../api/mcp/vault/testdata"
	expectAccept    = "ACCEPT"
	expectRefuse    = "REFUSE"
	refusedByEngine = "ENGINE"
	refusedByPage   = "PAGE"
)

type vectorFile[T any] struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Cases       []T    `json:"cases"`
}

func loadVectors[T any](t *testing.T, name, kind string) []T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name))
	require.NoError(t, err)
	var f vectorFile[T]
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&f), name)
	require.Equal(t, kind, f.Kind, name)
	require.NotEmpty(t, f.Cases, name)
	return f.Cases
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// outcome maps an error to a vector's expect value: ACCEPT, a close code's
// name, or REFUSE for a check that only says no.
func outcome(err error) string {
	if err == nil {
		return expectAccept
	}
	var code CloseError
	if errors.As(err, &code) {
		return code.String()
	}
	return expectRefuse
}

func TestLinkDerivationVectors(t *testing.T) {
	t.Parallel()
	type linkCase struct {
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		LinkToken string `json:"linkToken"`
		PSK       string `json:"psk"`
	}
	for _, c := range loadVectors[linkCase](t, "link-derivation.json", "LINK_DERIVATION") {
		lk, err := DeriveLink(c.Secret)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.LinkToken, lk.Token.Wire(), c.Name)
		require.Equal(t, c.PSK, hx(lk.PSK[:]), c.Name)
		parsed, err := ParseLinkToken(c.LinkToken)
		require.NoError(t, err, c.Name)
		require.Equal(t, lk.Token, parsed, c.Name)
	}
}

func TestEngineIDVectors(t *testing.T) {
	t.Parallel()
	type engineIDCase struct {
		Name        string `json:"name"`
		EngineKey   string `json:"engineKey"`
		EngineID    string `json:"engineId,omitempty"`
		Fingerprint string `json:"fingerprint,omitempty"`
		Expect      string `json:"expect"`
	}
	for _, c := range loadVectors[engineIDCase](t, "engine-id.json", "ENGINE_ID") {
		der, err := unb64(c.EngineKey)
		require.NoError(t, err, c.Name)
		_, err = ParseEngineKey(der)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		require.Equal(t, c.EngineID, EngineIDOf(der), c.Name)
		require.Equal(t, c.Fingerprint, FingerprintOf(c.EngineID), c.Name)
	}
}

func TestPaddingVectors(t *testing.T) {
	t.Parallel()
	type paddingCase struct {
		Name    string  `json:"name"`
		Content *string `json:"content,omitempty"`
		Padded  string  `json:"padded"`
		Expect  string  `json:"expect"`
	}
	for _, c := range loadVectors[paddingCase](t, "padding.json", "PADDING") {
		content, err := unpad(unhex(t, c.Padded))
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		require.NotNil(t, c.Content, c.Name)
		require.Equal(t, *c.Content, hx(content), c.Name)
		padded, err := pad(content)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Padded, hx(padded), c.Name)
	}
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

// pinnedSigner is the engine's signing key for a vector: ECDSA is randomized,
// so it returns the vector's signature, after checking that it signs exactly
// the bytes this package asks it to sign.
type pinnedSigner struct {
	t    *testing.T
	pub  *ecdsa.PublicKey
	spki []byte
	sig  []byte
}

func (p pinnedSigner) PublicKeySPKI() []byte { return p.spki }

func (p pinnedSigner) Sign(context SigningContext, body []byte) ([]byte, error) {
	require.Equal(p.t, ContextSession, context)
	require.NoError(p.t, VerifySignature(p.pub, context, body, p.sig), "the pinned sig signs the h this package computed")
	return p.sig, nil
}

func ephemeralKey(t *testing.T, scalarHex string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().NewPrivateKey(unhex(t, scalarHex))
	require.NoError(t, err)
	return k
}

// holding is a lookup for an engine that holds exactly link.
func holding(link LinkKeys) func(LinkToken) (PSK, bool) {
	return func(token LinkToken) (PSK, bool) {
		if token != link.Token {
			return PSK{}, false
		}
		return link.PSK, true
	}
}

func TestHandshakeVectors(t *testing.T) {
	t.Parallel()
	for _, c := range loadVectors[handshakeCase](t, "handshake.json", "HANDSHAKE") {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			checkHandshakeCase(t, c)
		})
	}
}

func checkHandshakeCase(t *testing.T, c handshakeCase) {
	t.Helper()
	transport := Transport(c.Transport)
	lk, err := DeriveLink(c.Secret)
	require.NoError(t, err)
	require.Equal(t, c.Prologue, hx(prologue(transport, lk.Token)))

	signing, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), unhex(t, c.EngineSigningPrivate))
	require.NoError(t, err)
	point, err := signing.PublicKey.Bytes()
	require.NoError(t, err)
	spki := spkiOfPoint(point)
	require.Equal(t, c.EngineKey, b64(spki))
	message1 := unhex(t, c.Message1)

	if c.RefusedBy == refusedByEngine {
		// SESSION_OPEN named the engine's link, and then (a Vault that
		// forwards consistently) whatever token message 1 carries, so the
		// engine's own lookup decides.
		_, err := ReadHello(message1, HelloCheck{Transport: transport, SessionToken: &lk.Token, Lookup: holding(lk)})
		require.Equal(t, c.Expect, outcome(err), "SESSION_OPEN named the link")
		if len(message1) >= headerLen+LinkTokenLen {
			carried := LinkToken(message1[headerLen : headerLen+LinkTokenLen])
			_, err = ReadHello(message1, HelloCheck{Transport: transport, SessionToken: &carried, Lookup: holding(lk)})
			require.Equal(t, c.Expect, outcome(err), "SESSION_OPEN named message 1's token")
		}
		return
	}

	// The page is honest in every other case: it writes message 1 itself.
	initiator, written, err := writeHello(transport, lk, ephemeralKey(t, c.PageEphemeralPrivate))
	require.NoError(t, err)
	require.Equal(t, c.Message1, hx(written))

	if c.Expect == expectAccept {
		responder, err := ReadHello(message1, HelloCheck{Transport: transport, SessionToken: &lk.Token, Lookup: holding(lk)})
		require.NoError(t, err)
		signer := pinnedSigner{t: t, pub: &signing.PublicKey, spki: spki, sig: mustUnb64(t, c.Sig)}
		message2, res, err := responder.writeWelcome(signer, ephemeralKey(t, c.EngineEphemeralPrivate))
		require.NoError(t, err)
		require.Equal(t, c.Message2, hx(message2), "message 2 byte for byte")
		requireKeys(t, c, res)
	}

	res, welcome, err := initiator.readWelcome(unhex(t, c.Message2))
	require.Equal(t, c.Expect, outcome(err))
	if err != nil {
		return
	}
	requireKeys(t, c, res)
	require.Equal(t, spki, welcome.EngineKey)
	require.Equal(t, EngineIDOf(spki), welcome.EngineID)
}

func mustUnb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := unb64(s)
	require.NoError(t, err)
	return b
}

func requireKeys(t *testing.T, c handshakeCase, res handshakeResult) {
	t.Helper()
	require.Equal(t, c.HandshakeHash, hx(res.h[:]))
	require.Equal(t, c.KeyPageToEngine, hx(res.pageToEngine[:]))
	require.Equal(t, c.KeyEngineToPage, hx(res.engineToPage[:]))
}

// sessionAt is a one-direction session with key and the counter at n.
func sessionAt(t *testing.T, key []byte, n uint64) *Session {
	t.Helper()
	var k [hashLen]byte
	copy(k[:], key)
	cs, err := newCipherState(&k)
	require.NoError(t, err)
	cs.n = n
	return &Session{send: cs, recv: cs}
}

func TestFrameVectors(t *testing.T) {
	t.Parallel()
	type frameCase struct {
		Name      string `json:"name"`
		Direction string `json:"direction"`
		Key       string `json:"key"`
		Counter   uint64 `json:"counter"`
		Content   string `json:"content,omitempty"`
		Frame     string `json:"frame"`
		Expect    string `json:"expect"`
	}
	for _, c := range loadVectors[frameCase](t, "frame.json", "FRAME") {
		frame := unhex(t, c.Frame)
		content, err := sessionAt(t, unhex(t, c.Key), c.Counter).Open(frame)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err != nil {
			continue
		}
		require.Equal(t, c.Content, string(content), c.Name)
		sealed, err := sessionAt(t, unhex(t, c.Key), c.Counter).Seal([]byte(c.Content))
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Frame, hx(sealed), c.Name)
	}
}

var vectorContexts = map[string]SigningContext{
	"VAULT_AUTH": ContextVaultAuth,
	"SESSION":    ContextSession,
	"RECEIPT":    ContextReceipt,
	"BOX_KEY":    ContextBoxKey,
	"ROTATE":     ContextRotate,
}

func TestSignatureVectors(t *testing.T) {
	t.Parallel()
	type signatureCase struct {
		Name      string `json:"name"`
		Context   string `json:"context"`
		PublicKey string `json:"publicKey"`
		Message   string `json:"message"`
		Sig       string `json:"sig"`
		Expect    string `json:"expect"`
	}
	seen := map[string]bool{}
	for _, c := range loadVectors[signatureCase](t, "signature.json", "SIGNATURE") {
		context, ok := vectorContexts[c.Context]
		require.True(t, ok, c.Name)
		err := verifyVectorSignature(context, c.PublicKey, unhex(t, c.Message), c.Sig)
		require.Equal(t, c.Expect, outcome(err), c.Name)
		if err == nil {
			seen[c.Context] = true
		}
	}
	require.Len(t, seen, len(vectorContexts), "every signing context has a valid vector")
}

// verifyVectorSignature checks a whole signed message: VerifySignature puts
// the context line in front itself, so a message under another line cannot
// reach it.
func verifyVectorSignature(context SigningContext, publicKey string, message []byte, sig string) error {
	body, ok := bytes.CutPrefix(message, []byte(context))
	if !ok {
		return ErrBadSignature
	}
	spki, err := unb64(publicKey)
	if err != nil {
		return err
	}
	pub, err := ParseEngineKey(spki)
	if err != nil {
		return err
	}
	raw, err := unb64(sig)
	if err != nil {
		return ErrBadSignature
	}
	return VerifySignature(pub, context, body, raw)
}

func TestCloseCodesMatchTheRegistry(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "..", "close-codes.json"))
	require.NoError(t, err)
	var registry struct {
		Codes []struct {
			Code int    `json:"code"`
			Name string `json:"name"`
		} `json:"codes"`
	}
	require.NoError(t, json.Unmarshal(raw, &registry))
	require.Len(t, registry.Codes, len(closeNames))
	for _, c := range registry.Codes {
		require.Equal(t, c.Name, CloseError(c.Code).String(), c.Code)
	}
	require.True(t, strings.HasPrefix(CloseError(1).String(), "CLOSE_"))
}
