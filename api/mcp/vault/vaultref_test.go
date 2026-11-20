package vault_test

// A reference implementation of the Vault channel (CONTRACT.md, Vault channel),
// only as far as the shared test vectors need: link derivation, engine ids,
// Noise_NNpsk0_P256_AESGCM_SHA256, frames and their padding, signing contexts
// and receipts. It is test-only. The engine's own handshake is VC1-3's.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	noiseProtocolName = "Noise_NNpsk0_P256_AESGCM_SHA256"
	hashLen           = 32

	wireVersion = 0x01
	typeHello   = 0x01
	typeWelcome = 0x02
	typeFrame   = 0x03
	headerLen   = 2

	pointLen     = 65
	tagLen       = 16
	linkTokenLen = 16
	pskLen       = 32
	secretLen    = 16
	message1Len  = headerLen + linkTokenLen + pointLen + tagLen // 99
	message2Max  = 1024

	lenPrefix  = 4
	padMin     = 1024
	padMax     = 32768
	contentMax = padMax - lenPrefix
	frameMax   = headerLen + padMax + tagLen // 32 786

	engineIDBytes  = 16
	fingerprintLen = 16
	fingerprintGrp = 4
	sigLen         = 64
	scalarLen      = 32
	nonceLen       = 12

	transportRelay  = "RELAY"
	transportDirect = "DIRECT"

	infoLinkToken = "basalt-vault-link.1"
	infoPSK       = "basalt-vault-psk.1"
	prologueLine  = "basalt-vault-prologue.1\n"

	expectAccept = "ACCEPT"
	expectRefuse = "REFUSE"
)

// The signing contexts (CONTRACT.md, Primitives and encodings).
var signingContexts = map[string]string{
	"VAULT_AUTH": "basalt-vault-engine.1\n",
	"SESSION":    "basalt-vault-session-sig.1\n",
	"RECEIPT":    "basalt-receipt.1\n",
	"BOX_KEY":    "basalt-engine-box-key.1\n",
	"ROTATE":     "basalt-engine-rotate.1\n",
	"CONNECT_COLLECT": "basalt-connect-collect.1\n",
}

// spkiP256Prefix is the DER of a P-256 SubjectPublicKeyInfo up to its
// uncompressed point: id-ecPublicKey, prime256v1, BIT STRING of 66 bytes.
var spkiP256Prefix = mustHex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

// vaultCloseError is a refusal: the close code a receiver closes with, or
// REFUSE when a check only returns false.
type vaultCloseError string

func (e vaultCloseError) Error() string { return string(e) }

const (
	errRefuse          vaultCloseError = expectRefuse
	errProtocol        vaultCloseError = "PROTOCOL"
	errVersion         vaultCloseError = "UNSUPPORTED_VERSION"
	errLinkRefused     vaultCloseError = "LINK_REFUSED"
	errHandshakeFailed vaultCloseError = "HANDSHAKE_FAILED"
	errFrameInvalid    vaultCloseError = "FRAME_INVALID"
	errTooLarge        vaultCloseError = "TOO_LARGE"
)

// outcome maps a check's error to the vector's expect value.
func outcome(err error) string {
	if err == nil {
		return expectAccept
	}
	var ce vaultCloseError
	if errors.As(err, &ce) {
		return string(ce)
	}
	return "UNEXPECTED: " + err.Error()
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes base64url without padding and refuses a non-canonical form.
func unb64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- Link secrets ---

type linkKeys struct {
	token []byte
	psk   []byte
}

func deriveLink(secret string) (linkKeys, error) {
	s, err := unb64(secret)
	if err != nil {
		return linkKeys{}, err
	}
	if len(s) != secretLen {
		return linkKeys{}, fmt.Errorf("secret is %d bytes", len(s))
	}
	token, err := hkdf.Key(sha256.New, s, nil, infoLinkToken, linkTokenLen)
	if err != nil {
		return linkKeys{}, fmt.Errorf("hkdf: %w", err)
	}
	psk, err := hkdf.Key(sha256.New, s, nil, infoPSK, pskLen)
	if err != nil {
		return linkKeys{}, fmt.Errorf("hkdf: %w", err)
	}
	return linkKeys{token: token, psk: psk}, nil
}

func prologue(transport string, token []byte) []byte {
	return []byte(prologueLine + transport + "\n" + b64(token))
}

// --- Engine keys ---

func signingKey(scalar []byte) (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	return k, nil
}

func spkiOf(pub *ecdsa.PublicKey) []byte {
	point, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	return cat(spkiP256Prefix, point)
}

// parseEngineKey reads a signing key's SPKI (base64url) and refuses any
// encoding but the 91-byte uncompressed P-256 form, and any point off the curve.
func parseEngineKey(spki string) (*ecdsa.PublicKey, error) {
	der, err := unb64(spki)
	if err != nil {
		return nil, errRefuse
	}
	if len(der) != len(spkiP256Prefix)+pointLen || !bytes.HasPrefix(der, spkiP256Prefix) {
		return nil, errRefuse
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), der[len(spkiP256Prefix):])
	if err != nil {
		return nil, errRefuse
	}
	return pub, nil
}

func engineIDOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return b64(sum[:engineIDBytes])
}

func fingerprintOf(engineID string) string {
	groups := make([]string, 0, fingerprintLen/fingerprintGrp)
	for i := 0; i < fingerprintLen; i += fingerprintGrp {
		groups = append(groups, engineID[i:i+fingerprintGrp])
	}
	return strings.Join(groups, " ")
}

// --- Signatures ---

func signRaw(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig := make([]byte, sigLen)
	r.FillBytes(sig[:sigLen/2])
	s.FillBytes(sig[sigLen/2:])
	return sig, nil
}

// verifySig checks a 64-byte r||s signature (base64url) over message.
func verifySig(pub *ecdsa.PublicKey, message []byte, sig string) error {
	raw, err := unb64(sig)
	if err != nil || len(raw) != sigLen {
		return errRefuse
	}
	r := new(big.Int).SetBytes(raw[:sigLen/2])
	s := new(big.Int).SetBytes(raw[sigLen/2:])
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errRefuse
	}
	return nil
}

// verifyContext checks a signature made under one signing context.
func verifyContext(context, publicKey string, message []byte, sig string) error {
	line, ok := signingContexts[context]
	if !ok {
		return fmt.Errorf("unknown context %q", context)
	}
	if !bytes.HasPrefix(message, []byte(line)) {
		return errRefuse
	}
	pub, err := parseEngineKey(publicKey)
	if err != nil {
		return err
	}
	return verifySig(pub, message, sig)
}

// --- Noise ---

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// noiseHKDF is Noise's HKDF (section 4.3) with HASHLEN 32.
func noiseHKDF(ck, ikm []byte, outputs int) [][]byte {
	temp := hmacSHA256(ck, ikm)
	out := make([][]byte, 0, outputs)
	var prev []byte
	for i := 1; i <= outputs; i++ {
		prev = hmacSHA256(temp, cat(prev, []byte{byte(i)}))
		out = append(out, prev)
	}
	return out
}

func noiseNonce(n uint64) []byte {
	nonce := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(nonce[nonceLen-8:], n)
	return nonce
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func seal(key []byte, n uint64, ad, plaintext []byte) []byte {
	return gcm(key).Seal(nil, noiseNonce(n), plaintext, ad)
}

func open(key []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	pt, err := gcm(key).Open(nil, noiseNonce(n), ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	return pt, nil
}

// symmetricState is Noise's SymmetricState with its CipherState (k, n).
// Every token this pattern uses comes after psk, so k is always set when a
// payload is encrypted.
type symmetricState struct {
	ck, h, k []byte
	n        uint64
}

func newSymmetricState(prologueBytes []byte) *symmetricState {
	h := make([]byte, hashLen)
	copy(h, noiseProtocolName)
	s := &symmetricState{ck: bytes.Clone(h), h: h}
	s.mixHash(prologueBytes)
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	sum := sha256.Sum256(cat(s.h, data))
	s.h = sum[:]
}

func (s *symmetricState) mixKey(ikm []byte) {
	out := noiseHKDF(s.ck, ikm, 2)
	s.ck, s.k, s.n = out[0], out[1], 0
}

func (s *symmetricState) mixKeyAndHash(ikm []byte) {
	out := noiseHKDF(s.ck, ikm, 3)
	s.ck = out[0]
	s.mixHash(out[1])
	s.k, s.n = out[2], 0
}

// mixE is the e token in psk mode: MixHash then MixKey of the public key, as
// the 65 bytes are, with no point check.
func (s *symmetricState) mixE(pub []byte) {
	s.mixHash(pub)
	s.mixKey(pub)
}

func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	ct := seal(s.k, s.n, s.h, plaintext)
	s.n++
	s.mixHash(ct)
	return ct
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	pt, err := open(s.k, s.n, s.h, ciphertext)
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

func (s *symmetricState) split() (k1, k2 []byte) {
	out := noiseHKDF(s.ck, nil, 2)
	return out[0], out[1]
}

// --- Handshake ---

type sessionKeys struct {
	h, pageToEngine, engineToPage []byte
}

func ephemeral(scalar []byte) *ecdh.PrivateKey {
	k, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		panic(err)
	}
	return k
}

// writeMessage1 is the page's HELLO, with ePub as given (a vector may pass an
// invalid point) and psk possibly not the link's.
func writeMessage1(transport string, token, psk, ePub []byte) ([]byte, *symmetricState) {
	s := newSymmetricState(prologue(transport, token))
	s.mixKeyAndHash(psk)
	s.mixE(ePub)
	tag := s.encryptAndHash(nil)
	return cat([]byte{wireVersion, typeHello}, token, ePub, tag), s
}

// readHeader checks a message's version and type.
func readHeader(msg []byte, want byte) error {
	if len(msg) < headerLen {
		return errProtocol
	}
	if msg[0] != wireVersion {
		return errVersion
	}
	if msg[1] != want {
		return errProtocol
	}
	return nil
}

// engineReadMessage1 is the engine's side, in the contract's order: header and
// length, the token, the tag, and only then the point.
//
// The tag-before-point order is not visible in the vectors: a failing tag and
// an invalid point both close with LINK_REFUSED, alike on purpose. It is
// pinned by TestEngineChecksTagBeforePoint, which watches the steps through
// readMessage1's onCheck hook.
func engineReadMessage1(transport string, held linkKeys, msg []byte) (*symmetricState, *ecdh.PublicKey, error) {
	return readMessage1(transport, held, msg, func(string) {})
}

// readMessage1 calls onCheck with the name of each check before it runs it.
func readMessage1(transport string, held linkKeys, msg []byte, onCheck func(step string)) (*symmetricState, *ecdh.PublicKey, error) {
	onCheck("header")
	if err := readHeader(msg, typeHello); err != nil {
		return nil, nil, err
	}
	if len(msg) != message1Len {
		return nil, nil, errProtocol
	}
	token := msg[headerLen : headerLen+linkTokenLen]
	ePub := msg[headerLen+linkTokenLen : headerLen+linkTokenLen+pointLen]
	tag := msg[headerLen+linkTokenLen+pointLen:]
	onCheck("token")
	if !hmac.Equal(token, held.token) {
		return nil, nil, errLinkRefused
	}
	onCheck("tag")
	s := newSymmetricState(prologue(transport, held.token))
	s.mixKeyAndHash(held.psk)
	s.mixE(ePub)
	if _, err := s.decryptAndHash(tag); err != nil {
		return nil, nil, errLinkRefused
	}
	onCheck("point")
	re, err := ecdh.P256().NewPublicKey(ePub)
	if err != nil {
		return nil, nil, errLinkRefused
	}
	return s, re, nil
}

type welcomePayload struct {
	EngineKey string `json:"engineKey"`
	Sig       string `json:"sig"`
}

// writeMessage2 is the engine's WELCOME. payload builds the plaintext from h
// after e and ee, so a vector can sign it or break it.
func writeMessage2(s *symmetricState, re *ecdh.PublicKey, e *ecdh.PrivateKey, payload func(h []byte) []byte) ([]byte, sessionKeys) {
	ePub := e.PublicKey().Bytes()
	s.mixE(ePub)
	dh, err := e.ECDH(re)
	if err != nil {
		panic(err)
	}
	s.mixKey(dh)
	ct := s.encryptAndHash(payload(bytes.Clone(s.h)))
	k1, k2 := s.split()
	return cat([]byte{wireVersion, typeWelcome}, ePub, ct), sessionKeys{h: s.h, pageToEngine: k1, engineToPage: k2}
}

// pageReadMessage2 is the page's side: point, decrypt, closed schema, signature.
func pageReadMessage2(s *symmetricState, e *ecdh.PrivateKey, msg []byte) (sessionKeys, error) {
	if err := readHeader(msg, typeWelcome); err != nil {
		return sessionKeys{}, err
	}
	if len(msg) > message2Max {
		return sessionKeys{}, errTooLarge
	}
	if len(msg) < headerLen+pointLen+tagLen {
		return sessionKeys{}, errHandshakeFailed
	}
	rePub := msg[headerLen : headerLen+pointLen]
	re, err := ecdh.P256().NewPublicKey(rePub)
	if err != nil {
		return sessionKeys{}, errHandshakeFailed
	}
	s.mixE(rePub)
	dh, err := e.ECDH(re)
	if err != nil {
		return sessionKeys{}, errHandshakeFailed
	}
	s.mixKey(dh)
	signed := bytes.Clone(s.h)
	pt, err := s.decryptAndHash(msg[headerLen+pointLen:])
	if err != nil {
		return sessionKeys{}, errHandshakeFailed
	}
	var p welcomePayload
	if err := strictJSON(pt, &p); err != nil || p.EngineKey == "" || p.Sig == "" {
		return sessionKeys{}, errHandshakeFailed
	}
	pub, err := parseEngineKey(p.EngineKey)
	if err != nil {
		return sessionKeys{}, errHandshakeFailed
	}
	if err := verifySig(pub, cat([]byte(signingContexts["SESSION"]), signed), p.Sig); err != nil {
		return sessionKeys{}, errHandshakeFailed
	}
	k1, k2 := s.split()
	return sessionKeys{h: s.h, pageToEngine: k1, engineToPage: k2}, nil
}

func strictJSON(raw []byte, v any) error {
	if !utf8.Valid(raw) {
		return errors.New("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// --- Frames ---

func bucket(contentLen int) int {
	size := padMin
	for size < lenPrefix+contentLen {
		size *= 2
	}
	return size
}

func pad(content []byte) []byte {
	if len(content) > contentMax {
		panic("content over one frame")
	}
	out := make([]byte, bucket(len(content)))
	binary.BigEndian.PutUint32(out, uint32(len(content)))
	copy(out[lenPrefix:], content)
	return out
}

func unpad(padded []byte) ([]byte, error) {
	if len(padded) < lenPrefix {
		return nil, errFrameInvalid
	}
	n := binary.BigEndian.Uint32(padded)
	if n > contentMax || len(padded) != bucket(int(n)) {
		return nil, errFrameInvalid
	}
	end := lenPrefix + int(n)
	for _, b := range padded[end:] {
		if b != 0 {
			return nil, errFrameInvalid
		}
	}
	return padded[lenPrefix:end], nil
}

var frameHeader = []byte{wireVersion, typeFrame}

func sealFrame(key []byte, n uint64, padded []byte) []byte {
	return cat(frameHeader, seal(key, n, frameHeader, padded))
}

// openFrame is a receiver's check with its own key and counter.
func openFrame(key []byte, n uint64, frame []byte) ([]byte, error) {
	if len(frame) > frameMax {
		return nil, errTooLarge
	}
	if err := readHeader(frame, typeFrame); err != nil {
		return nil, err
	}
	padded, err := open(key, n, frame[:headerLen], frame[headerLen:])
	if err != nil {
		return nil, errFrameInvalid
	}
	return unpad(padded)
}

// --- Receipts ---

const receiptPrefix = "basalt-receipt.1."

type receiptPayload struct {
	Format   *int    `json:"format"`
	Kind     string  `json:"kind"`
	ItemID   string  `json:"itemId"`
	Status   string  `json:"status"`
	Headline string  `json:"headline"`
	RowsHash string  `json:"rowsHash"`
	Agent    string  `json:"agent"`
	EngineID string  `json:"engineId"`
	At       string  `json:"at"`
	ChangeID *string `json:"changeId,omitempty"`
}

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	rowsHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	engineIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	rfc3339Pattern  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	receiptKinds    = map[string]bool{"APPROVAL": true, "REVERT": true}
	receiptStatuses = map[string]bool{"APPROVED": true, "APPLIED": true, "APPLYING": true}
)

const headlineMax = 500

// verifyReceipt checks a receipt token against the key the verifier already
// expects: the signature, then engineId, then the closed schema.
func verifyReceipt(token, expectedKey string) (receiptPayload, error) {
	rest, ok := strings.CutPrefix(token, receiptPrefix)
	if !ok {
		return receiptPayload{}, errRefuse
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return receiptPayload{}, errRefuse
	}
	payload, err := unb64(parts[0])
	if err != nil {
		return receiptPayload{}, errRefuse
	}
	pub, err := parseEngineKey(expectedKey)
	if err != nil {
		return receiptPayload{}, err
	}
	if err := verifySig(pub, cat([]byte(signingContexts["RECEIPT"]), payload), parts[1]); err != nil {
		return receiptPayload{}, err
	}
	var p receiptPayload
	if err := strictJSON(payload, &p); err != nil {
		return receiptPayload{}, errRefuse
	}
	keyDER, err := unb64(expectedKey)
	if err != nil {
		return receiptPayload{}, errRefuse
	}
	if p.EngineID != engineIDOf(keyDER) {
		return receiptPayload{}, errRefuse
	}
	if !receiptValid(p) {
		return receiptPayload{}, errRefuse
	}
	return p, nil
}

func receiptValid(p receiptPayload) bool {
	headline := utf8.RuneCountInString(p.Headline)
	return p.Format != nil && *p.Format == 1 &&
		receiptKinds[p.Kind] && receiptStatuses[p.Status] &&
		uuidPattern.MatchString(p.ItemID) &&
		headline >= 1 && headline <= headlineMax &&
		rowsHashPattern.MatchString(p.RowsHash) &&
		p.Agent != "" &&
		engineIDPattern.MatchString(p.EngineID) &&
		rfc3339Pattern.MatchString(p.At) &&
		(p.ChangeID == nil || uuidPattern.MatchString(*p.ChangeID))
}
