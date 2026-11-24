package channel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// prologueLine starts the prologue (CONTRACT.md, Vault channel, Handshake).
const prologueLine = "basalt-vault-prologue.1\n"

// prologue binds the version, the transport and the link's token (as its
// base64url text) into h.
func prologue(transport Transport, token LinkToken) []byte {
	return []byte(prologueLine + string(transport) + "\n" + token.Wire())
}

// readHeader checks a message's version, then its type.
func readHeader(msg []byte, want byte) error {
	if len(msg) < headerLen {
		return ErrProtocol
	}
	if msg[0] != wireVersion {
		return ErrUnsupportedVersion
	}
	if msg[1] != want {
		return ErrProtocol
	}
	return nil
}

// welcomePayload is message 2's payload
// (api/mcp/vault/handshake-payload.schema.json), in this field order.
type welcomePayload struct {
	EngineKey string `json:"engineKey"`
	Sig       string `json:"sig"`
}

// handshakeResult is what both sides hold after Split, before the keys go
// into a Session.
type handshakeResult struct {
	h            [hashLen]byte
	pageToEngine [hashLen]byte
	engineToPage [hashLen]byte
}

func (r *handshakeResult) erase() {
	clear(r.pageToEngine[:])
	clear(r.engineToPage[:])
}

// --- The engine (responder) ---

// HelloCheck is what the engine knows when message 1 arrives.
type HelloCheck struct {
	// Transport is the socket the session came on.
	Transport Transport
	// SessionToken is SESSION_OPEN's linkToken, required: message 1's
	// token must equal it.
	SessionToken *LinkToken
	// Lookup returns the psk of the live link with this token: false for a
	// token the engine does not hold, or whose link expired or was revoked.
	Lookup func(LinkToken) (PSK, bool)
}

// Responder is the engine's handshake after a valid message 1, ready to
// write message 2. It is single use.
type Responder struct {
	ss   *symmetricState
	re   *ecdh.PublicKey
	used bool
}

// ReadHello checks handshake message 1 in the contract's order: version,
// type and the exact length; the token (SESSION_OPEN's on RELAY, and one the
// engine holds); the tag; and only then the ephemeral point. Every refusal
// from the token on is ErrLinkRefused, alike, and a token that is not live
// still runs the tag check (under a zero psk, then refused), so a probe can
// tell a live token from a dead one neither by the answer nor by the time
// the tag check takes. Rate checks (CONTRACT.md, Limits) are the caller's,
// before this call.
func ReadHello(msg []byte, check HelloCheck) (*Responder, error) {
	return readHello(msg, check, func(string) {})
}

// readHello calls onCheck with each check's name before running it, so a
// test can pin the order.
func readHello(msg []byte, check HelloCheck, onCheck func(step string)) (*Responder, error) {
	if !check.Transport.valid() || check.Lookup == nil {
		return nil, errors.New("vault channel: a hello check needs a transport and a lookup")
	}
	if check.SessionToken == nil {
		return nil, errors.New("vault channel: a hello check needs SESSION_OPEN's token")
	}
	onCheck("header")
	if err := readHeader(msg, typeHello); err != nil {
		return nil, err
	}
	if len(msg) != Message1Len {
		return nil, ErrProtocol
	}
	rest := msg[headerLen:]
	token := LinkToken(rest[:LinkTokenLen])
	ePub := rest[LinkTokenLen : LinkTokenLen+PointLen]
	tag := rest[LinkTokenLen+PointLen:]

	onCheck("token")
	live := subtle.ConstantTimeCompare(token[:], check.SessionToken[:]) == 1
	held, ok := check.Lookup(token)
	defer held.Zero()
	// A token that is not live still goes through the tag check, under an
	// all-zero psk, so a dead token and a live one with a wrong psk take
	// the same work. The result is refused whatever the tag says: anyone
	// can make a tag under the zero psk.
	var psk PSK
	defer psk.Zero()
	live = live && ok
	if live {
		psk = held
	}

	onCheck("tag")
	ss := newSymmetricState(prologue(check.Transport, token))
	ss.mixKeyAndHash(psk[:])
	ss.mixE(ePub)
	_, tagErr := ss.decryptAndHash(tag)
	if tagErr != nil || !live {
		ss.erase()
		return nil, ErrLinkRefused
	}

	onCheck("point")
	re, err := ecdh.P256().NewPublicKey(ePub)
	if err != nil {
		ss.erase()
		return nil, ErrLinkRefused
	}
	return &Responder{ss: ss, re: re}, nil
}

// WriteWelcome makes the engine's ephemeral key, writes handshake message 2
// signed by signer, and returns the engine's Session.
func (r *Responder) WriteWelcome(signer Signer) ([]byte, *Session, error) {
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ephemeral key: %w", err)
	}
	msg, res, err := r.writeWelcome(signer, e)
	if err != nil {
		return nil, nil, err
	}
	defer res.erase()
	s, err := newSession(res.h, &res.engineToPage, &res.pageToEngine)
	if err != nil {
		return nil, nil, err
	}
	return msg, s, nil
}

// writeWelcome is message 2 with a given ephemeral key (the vectors fix it).
func (r *Responder) writeWelcome(signer Signer, e *ecdh.PrivateKey) ([]byte, handshakeResult, error) {
	if r.used {
		return nil, handshakeResult{}, errors.New("vault channel: the handshake was already answered")
	}
	r.used = true
	ss := r.ss
	defer ss.erase()

	ePub := e.PublicKey().Bytes()
	ss.mixE(ePub)
	dh, err := e.ECDH(r.re)
	if err != nil {
		return nil, handshakeResult{}, fmt.Errorf("ecdh: %w", err)
	}
	ss.mixKey(dh)
	clear(dh)

	signed := ss.h
	sig, err := signer.Sign(ContextSession, signed[:])
	if err != nil {
		return nil, handshakeResult{}, err
	}
	payload, err := json.Marshal(welcomePayload{EngineKey: b64(signer.PublicKeySPKI()), Sig: b64(sig)})
	if err != nil {
		return nil, handshakeResult{}, fmt.Errorf("welcome payload: %w", err)
	}
	ct, err := ss.encryptAndHash(payload)
	if err != nil {
		return nil, handshakeResult{}, err
	}
	msg := concat([]byte{wireVersion, typeWelcome}, ePub, ct)
	if len(msg) > Message2Max {
		return nil, handshakeResult{}, ErrTooLarge
	}
	res := handshakeResult{h: ss.h}
	res.pageToEngine, res.engineToPage = ss.split()
	return msg, res, nil
}

// --- The page (initiator) ---

// Initiator is the page's side of the handshake after message 1. The portal
// runs it in WebCrypto (web/lib); this Go side exists so the engine's
// sessions can be tested end to end without a browser. It is single use.
type Initiator struct {
	ss   *symmetricState
	e    *ecdh.PrivateKey
	used bool
}

// WriteHello starts a session for link over transport and returns message 1.
// The engine only answers; this is the page's side, the reference the vector
// and handshake tests drive.
func WriteHello(transport Transport, link LinkKeys) (*Initiator, []byte, error) {
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ephemeral key: %w", err)
	}
	return writeHello(transport, link, e)
}

func writeHello(transport Transport, link LinkKeys, e *ecdh.PrivateKey) (*Initiator, []byte, error) {
	if !transport.valid() {
		return nil, nil, fmt.Errorf("vault channel: unknown transport %q", transport)
	}
	ePub := e.PublicKey().Bytes()
	ss := newSymmetricState(prologue(transport, link.Token))
	ss.mixKeyAndHash(link.PSK[:])
	ss.mixE(ePub)
	tag, err := ss.encryptAndHash(nil)
	if err != nil {
		return nil, nil, err
	}
	msg := concat([]byte{wireVersion, typeHello}, link.Token[:], ePub, tag)
	return &Initiator{ss: ss, e: e}, msg, nil
}

// Welcome is what the page learns from a valid message 2.
type Welcome struct {
	// EngineKey is the engine's signing key SPKI DER, as signed.
	EngineKey []byte
	// EngineID is EngineKey's id; on RELAY it is shown, not pinned (VC-42).
	EngineID string
}

// ReadWelcome checks message 2 in the reference's order: version and type,
// size, the engine's point, decryption, the closed payload schema, the key's
// encoding and the signature over h after e and ee. Any failure after the
// size is ErrHandshakeFailed.
func (i *Initiator) ReadWelcome(msg []byte) (*Session, Welcome, error) {
	res, w, err := i.readWelcome(msg)
	if err != nil {
		return nil, Welcome{}, err
	}
	defer res.erase()
	s, err := newSession(res.h, &res.pageToEngine, &res.engineToPage)
	if err != nil {
		return nil, Welcome{}, err
	}
	return s, w, nil
}

func (i *Initiator) readWelcome(msg []byte) (handshakeResult, Welcome, error) {
	if i.used {
		return handshakeResult{}, Welcome{}, errors.New("vault channel: the handshake was already answered")
	}
	i.used = true
	ss := i.ss
	defer ss.erase()
	if err := readHeader(msg, typeWelcome); err != nil {
		return handshakeResult{}, Welcome{}, err
	}
	if len(msg) > Message2Max {
		return handshakeResult{}, Welcome{}, ErrTooLarge
	}
	if len(msg) < headerLen+PointLen+tagLen {
		return handshakeResult{}, Welcome{}, ErrHandshakeFailed
	}
	rePub := msg[headerLen : headerLen+PointLen]
	re, err := ecdh.P256().NewPublicKey(rePub)
	if err != nil {
		return handshakeResult{}, Welcome{}, ErrHandshakeFailed
	}
	ss.mixE(rePub)
	dh, err := i.e.ECDH(re)
	if err != nil {
		return handshakeResult{}, Welcome{}, ErrHandshakeFailed
	}
	ss.mixKey(dh)
	clear(dh)
	signed := ss.h
	pt, err := ss.decryptAndHash(msg[headerLen+PointLen:])
	if err != nil {
		return handshakeResult{}, Welcome{}, ErrHandshakeFailed
	}
	w, err := checkWelcome(pt, signed[:])
	if err != nil {
		return handshakeResult{}, Welcome{}, ErrHandshakeFailed
	}
	res := handshakeResult{h: ss.h}
	res.pageToEngine, res.engineToPage = ss.split()
	return res, w, nil
}

// checkWelcome parses message 2's closed payload and verifies its signature.
func checkWelcome(pt, signed []byte) (Welcome, error) {
	var p welcomePayload
	if err := strictJSON(pt, &p); err != nil {
		return Welcome{}, err
	}
	spki, err := Unb64(p.EngineKey)
	if err != nil {
		return Welcome{}, err
	}
	pub, err := ParseEngineKey(spki)
	if err != nil {
		return Welcome{}, err
	}
	sig, err := Unb64(p.Sig)
	if err != nil {
		return Welcome{}, err
	}
	if err := VerifySignature(pub, ContextSession, signed, sig); err != nil {
		return Welcome{}, err
	}
	return Welcome{EngineKey: spki, EngineID: EngineIDOf(spki)}, nil
}

// strictJSON decodes one JSON object with no unknown fields, no trailing
// data and both of welcomePayload's fields present.
func strictJSON(raw []byte, p *welcomePayload) error {
	if !utf8.Valid(raw) {
		return errors.New("not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	if p.EngineKey == "" || p.Sig == "" {
		return errors.New("a required field is missing")
	}
	return nil
}
