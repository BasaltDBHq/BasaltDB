package channel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newLink(t *testing.T) (string, LinkKeys) {
	t.Helper()
	secret := b64(randomBytes(t, SecretLen))
	lk, err := DeriveLink(secret)
	require.NoError(t, err)
	return secret, lk
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func newKeys(t *testing.T) *EngineKeys {
	t.Helper()
	k, err := GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return k
}

func relayCheck(lk LinkKeys) HelloCheck {
	return HelloCheck{Transport: TransportRelay, SessionToken: &lk.Token, Lookup: holding(lk)}
}

// handshake runs a whole handshake over RELAY with real keys.
func handshake(t *testing.T, keys *EngineKeys, lk LinkKeys) (page, engine *Session, w Welcome) {
	t.Helper()
	init, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	require.Len(t, m1, Message1Len)
	resp, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	m2, engine, err := resp.WriteWelcome(keys)
	require.NoError(t, err)
	require.LessOrEqual(t, len(m2), Message2Max)
	page, w, err = init.ReadWelcome(m2)
	require.NoError(t, err)
	return page, engine, w
}

func TestHandshakeAndFramesRoundTrip(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	_, lk := newLink(t)
	page, engine, w := handshake(t, keys, lk)
	require.Equal(t, keys.EngineID(), w.EngineID)
	require.Equal(t, keys.PublicKeySPKI(), w.EngineKey)
	require.Equal(t, page.Hash(), engine.Hash())

	for i, content := range [][]byte{nil, []byte(`{"type":"REQUEST","id":1}`), bytes.Repeat([]byte("x"), ContentMax)} {
		frame, err := page.Seal(content)
		require.NoError(t, err, i)
		got, err := engine.Open(frame)
		require.NoError(t, err, i)
		require.Equal(t, len(content), len(got), i)

		frame, err = engine.Seal(content)
		require.NoError(t, err, i)
		got, err = page.Open(frame)
		require.NoError(t, err, i)
		require.Equal(t, len(content), len(got), i)
	}
}

func TestEngineRefusesAWrongPSK(t *testing.T) {
	t.Parallel()
	_, lk := newLink(t)
	_, other := newLink(t)
	// The page holds the right token with another link's psk.
	_, m1, err := WriteHello(TransportRelay, LinkKeys{Token: lk.Token, PSK: other.PSK})
	require.NoError(t, err)
	_, err = ReadHello(m1, relayCheck(lk))
	require.ErrorIs(t, err, ErrLinkRefused)
}

func TestPageRefusesAnEngineWithAnotherPSK(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	_, lk := newLink(t)
	_, other := newLink(t)
	init, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	// An engine that accepts anything for this token, with the wrong psk,
	// cannot even get past the tag.
	_, err = ReadHello(m1, HelloCheck{Transport: TransportRelay, SessionToken: &lk.Token, Lookup: func(LinkToken) (PSK, bool) { return other.PSK, true }})
	require.ErrorIs(t, err, ErrLinkRefused)
	// A Vault-side impostor that skips the tag and answers under another
	// psk is refused by the page.
	ss := newSymmetricState(prologue(TransportRelay, lk.Token))
	ss.mixKeyAndHash(other.PSK[:])
	ss.mixE(m1[headerLen+LinkTokenLen : headerLen+LinkTokenLen+PointLen])
	re, err := init.e.PublicKey().Curve().NewPublicKey(m1[headerLen+LinkTokenLen : headerLen+LinkTokenLen+PointLen])
	require.NoError(t, err)
	m2, _, err := (&Responder{ss: ss, re: re}).WriteWelcome(keys)
	require.NoError(t, err)
	_, _, err = init.ReadWelcome(m2)
	require.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestEngineRefusesATokenOtherThanSessionOpens(t *testing.T) {
	t.Parallel()
	_, lk := newLink(t)
	_, other := newLink(t)
	_, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	// The engine holds both links; SESSION_OPEN named the other one.
	both := func(token LinkToken) (PSK, bool) {
		switch token {
		case lk.Token:
			return lk.PSK, true
		case other.Token:
			return other.PSK, true
		default:
			return PSK{}, false
		}
	}
	_, err = ReadHello(m1, HelloCheck{Transport: TransportRelay, SessionToken: &other.Token, Lookup: both})
	require.ErrorIs(t, err, ErrLinkRefused)
	_, err = ReadHello(m1, HelloCheck{Transport: TransportRelay, SessionToken: &lk.Token, Lookup: both})
	require.NoError(t, err)
}

func TestEngineRefusesEveryTamperedByteOfMessage1(t *testing.T) {
	t.Parallel()
	_, lk := newLink(t)
	_, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	for i := range m1 {
		tampered := bytes.Clone(m1)
		tampered[i] ^= 0x01
		_, err := ReadHello(tampered, relayCheck(lk))
		want := ErrLinkRefused
		switch i {
		case 0:
			want = ErrUnsupportedVersion
		case 1:
			want = ErrProtocol
		}
		require.ErrorIs(t, err, want, "byte %d", i)
	}
}

func TestPageRefusesEveryTamperedByteOfMessage2(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	_, lk := newLink(t)
	for _, i := range []int{0, 1, 2, headerLen + PointLen - 1, headerLen + PointLen, -1} {
		init, m1, err := WriteHello(TransportRelay, lk)
		require.NoError(t, err)
		resp, err := ReadHello(m1, relayCheck(lk))
		require.NoError(t, err)
		m2, _, err := resp.WriteWelcome(keys)
		require.NoError(t, err)
		at := i
		if at < 0 {
			at = len(m2) - 1
		}
		m2[at] ^= 0x01
		_, _, err = init.ReadWelcome(m2)
		want := ErrHandshakeFailed
		switch at {
		case 0:
			want = ErrUnsupportedVersion
		case 1:
			want = ErrProtocol
		}
		require.ErrorIs(t, err, want, "byte %d", at)
	}
}

func TestHandshakeSizes(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	_, lk := newLink(t)
	_, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)

	for _, m := range [][]byte{m1[:Message1Len-1], append(bytes.Clone(m1), 0), m1[:1], nil} {
		_, err := ReadHello(m, relayCheck(lk))
		require.ErrorIs(t, err, ErrProtocol, len(m))
	}

	init, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	resp, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	m2, _, err := resp.WriteWelcome(keys)
	require.NoError(t, err)
	oversize := append(bytes.Clone(m2), make([]byte, Message2Max-len(m2)+1)...)
	_, _, err = init.ReadWelcome(oversize)
	require.ErrorIs(t, err, ErrTooLarge)

	init, _, err = WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	_, _, err = init.ReadWelcome(m2[:headerLen+PointLen+tagLen-1])
	require.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestFrameSizes(t *testing.T) {
	t.Parallel()
	page, engine, _ := handshake(t, newKeys(t), mustLink(t))

	_, err := page.Seal(make([]byte, ContentMax+1))
	require.ErrorIs(t, err, ErrTooLarge, "content over one frame is the caller's to continue")
	frame, err := page.Seal(make([]byte, ContentMax))
	require.NoError(t, err)
	require.Len(t, frame, FrameMax)

	_, err = engine.Open(append(frame, 0))
	require.ErrorIs(t, err, ErrTooLarge)
	_, err = engine.Open(frame)
	require.ErrorIs(t, err, ErrTooLarge, "a session that refused stays closed")
}

func mustLink(t *testing.T) LinkKeys {
	t.Helper()
	_, lk := newLink(t)
	return lk
}

func TestFramesRefuseReplayReorderAndReflection(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	lk := mustLink(t)

	t.Run("replay", func(t *testing.T) {
		page, engine, _ := handshake(t, keys, lk)
		first, err := page.Seal([]byte("one"))
		require.NoError(t, err)
		_, err = engine.Open(first)
		require.NoError(t, err)
		_, err = engine.Open(first)
		require.ErrorIs(t, err, ErrFrameInvalid)
		second, err := page.Seal([]byte("two"))
		require.NoError(t, err)
		_, err = engine.Open(second)
		require.ErrorIs(t, err, ErrFrameInvalid, "nothing is accepted after a refusal")
	})
	t.Run("reorder", func(t *testing.T) {
		page, engine, _ := handshake(t, keys, lk)
		_, err := page.Seal([]byte("one"))
		require.NoError(t, err)
		second, err := page.Seal([]byte("two"))
		require.NoError(t, err)
		_, err = engine.Open(second)
		require.ErrorIs(t, err, ErrFrameInvalid)
	})
	t.Run("reflection", func(t *testing.T) {
		page, _, _ := handshake(t, keys, lk)
		frame, err := page.Seal([]byte("one"))
		require.NoError(t, err)
		_, err = page.Open(frame)
		require.ErrorIs(t, err, ErrFrameInvalid)
	})
	t.Run("another session", func(t *testing.T) {
		page, _, _ := handshake(t, keys, lk)
		_, engine2, _ := handshake(t, keys, lk)
		frame, err := page.Seal([]byte("one"))
		require.NoError(t, err)
		_, err = engine2.Open(frame)
		require.ErrorIs(t, err, ErrFrameInvalid)
	})
	t.Run("tampered", func(t *testing.T) {
		for _, at := range []int{headerLen, headerLen + 5, -1} {
			page, engine, _ := handshake(t, keys, lk)
			frame, err := page.Seal([]byte("one"))
			require.NoError(t, err)
			if at < 0 {
				at = len(frame) - 1
			}
			frame[at] ^= 0x01
			_, err = engine.Open(frame)
			require.ErrorIs(t, err, ErrFrameInvalid, at)
		}
	})
	t.Run("closed", func(t *testing.T) {
		page, engine, _ := handshake(t, keys, lk)
		frame, err := page.Seal([]byte("one"))
		require.NoError(t, err)
		engine.Close()
		_, err = engine.Open(frame)
		require.ErrorIs(t, err, errSessionClosed)
		_, err = engine.Seal(nil)
		require.ErrorIs(t, err, errSessionClosed)
	})
}

// TestReplayedMessage1LeadsNowhere: the engine answers a replayed hello with
// a fresh ephemeral key, so the replayer gets a different session it cannot
// read, and frames of the first session do not open in it.
func TestReplayedMessage1LeadsNowhere(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	lk := mustLink(t)
	init, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)

	resp1, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	m2a, engine1, err := resp1.WriteWelcome(keys)
	require.NoError(t, err)
	resp2, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	m2b, engine2, err := resp2.WriteWelcome(keys)
	require.NoError(t, err)
	require.NotEqual(t, m2a, m2b)
	require.NotEqual(t, engine1.Hash(), engine2.Hash())

	page, _, err := init.ReadWelcome(m2a)
	require.NoError(t, err)
	frame, err := page.Seal([]byte("for the first session only"))
	require.NoError(t, err)
	_, err = engine2.Open(frame)
	require.ErrorIs(t, err, ErrFrameInvalid)

	// A message 2 replayed to the page, or to a new page, fails.
	_, _, err = init.ReadWelcome(m2a)
	require.Error(t, err, "a handshake is answered once")
	init2, _, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	_, _, err = init2.ReadWelcome(m2a)
	require.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestResponderAnswersOnce(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	lk := mustLink(t)
	_, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	resp, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	_, _, err = resp.WriteWelcome(keys)
	require.NoError(t, err)
	_, _, err = resp.WriteWelcome(keys)
	require.Error(t, err)
}

func TestTransportIsBoundInThePrologue(t *testing.T) {
	t.Parallel()
	lk := mustLink(t)
	_, m1, err := WriteHello(TransportDirect, lk)
	require.NoError(t, err)
	_, err = ReadHello(m1, relayCheck(lk))
	require.ErrorIs(t, err, ErrLinkRefused)
	_, err = ReadHello(m1, HelloCheck{Transport: TransportDirect, Lookup: holding(lk)})
	require.NoError(t, err)

	_, _, err = WriteHello("CARRIER_PIGEON", lk)
	require.Error(t, err)
	_, err = ReadHello(m1, HelloCheck{Transport: "CARRIER_PIGEON", Lookup: holding(lk)})
	require.Error(t, err)
	_, err = ReadHello(m1, HelloCheck{Transport: TransportDirect})
	require.Error(t, err, "a lookup is required")
	_, err = ReadHello(m1, HelloCheck{Transport: TransportRelay, Lookup: holding(lk)})
	require.Error(t, err, "RELAY needs SESSION_OPEN's token")
	_, err = ReadHello(m1, HelloCheck{Transport: TransportDirect, Lookup: holding(mustLink(t))})
	require.ErrorIs(t, err, ErrLinkRefused, "a token the engine does not hold")
}

// TestEngineChecksTagBeforePoint pins what the vectors cannot show: the tag
// is checked before any point arithmetic, so a bad tag over an invalid point
// stops at the tag (both close with LINK_REFUSED).
func TestEngineChecksTagBeforePoint(t *testing.T) {
	t.Parallel()
	lk := mustLink(t)
	other := mustLink(t)
	page, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	offCurve := page.PublicKey().Bytes()
	offCurve[len(offCurve)-1] ^= 1

	run := func(link LinkKeys) ([]string, error) {
		_, m1, err := writeHelloRawPoint(TransportRelay, lk.Token, link.PSK, offCurve)
		require.NoError(t, err)
		var steps []string
		_, err = readHello(m1, relayCheck(lk), func(step string) { steps = append(steps, step) })
		return steps, err
	}
	steps, err := run(other)
	require.ErrorIs(t, err, ErrLinkRefused)
	require.Equal(t, []string{"header", "token", "tag"}, steps)
	steps, err = run(lk)
	require.ErrorIs(t, err, ErrLinkRefused)
	require.Equal(t, []string{"header", "token", "tag", "point"}, steps)
}

// writeHelloRawPoint is a page's message 1 with any 65 bytes as e, as a
// hostile page could send.
func writeHelloRawPoint(transport Transport, token LinkToken, psk PSK, ePub []byte) (*symmetricState, []byte, error) {
	ss := newSymmetricState(prologue(transport, token))
	ss.mixKeyAndHash(psk[:])
	ss.mixE(ePub)
	tag, err := ss.encryptAndHash(nil)
	if err != nil {
		return nil, nil, err
	}
	return ss, concat([]byte{wireVersion, typeHello}, token[:], ePub, tag), nil
}

func TestHandshakeErasesItsChainingKeys(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	lk := mustLink(t)
	init, m1, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	resp, err := ReadHello(m1, relayCheck(lk))
	require.NoError(t, err)
	m2, _, err := resp.WriteWelcome(keys)
	require.NoError(t, err)
	_, _, err = init.ReadWelcome(m2)
	require.NoError(t, err)
	var zero [hashLen]byte
	for _, ss := range []*symmetricState{resp.ss, init.ss} {
		require.Equal(t, zero, ss.ck)
		require.Equal(t, zero, ss.k)
	}
}

func TestKeyLengths(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, SecretLen - 1, SecretLen + 1, 32} {
		_, err := DeriveLink(b64(make([]byte, n)))
		require.Error(t, err, n)
	}
	_, err := DeriveLink("not base64url!")
	require.Error(t, err)
	_, err = DeriveLink(b64(make([]byte, SecretLen)) + "=")
	require.Error(t, err, "padding is not base64url without padding")

	for _, n := range []int{LinkTokenLen - 1, LinkTokenLen + 1} {
		_, err := ParseLinkToken(b64(make([]byte, n)))
		require.Error(t, err, n)
	}

	spki := newKeys(t).PublicKeySPKI()
	for _, k := range [][]byte{spki[:SPKILen-1], append(bytes.Clone(spki), 0), nil} {
		_, err := ParseEngineKey(k)
		require.ErrorIs(t, err, ErrBadKey, len(k))
	}

	keys := newKeys(t)
	pub, err := ParseEngineKey(keys.PublicKeySPKI())
	require.NoError(t, err)
	sig, err := keys.Sign(ContextReceipt, []byte("body"))
	require.NoError(t, err)
	require.NoError(t, VerifySignature(pub, ContextReceipt, []byte("body"), sig))
	for _, s := range [][]byte{sig[:SigLen-1], append(bytes.Clone(sig), 0), nil} {
		require.ErrorIs(t, VerifySignature(pub, ContextReceipt, []byte("body"), s), ErrBadSignature, len(s))
	}
	require.ErrorIs(t, VerifySignature(pub, ContextSession, []byte("body"), sig), ErrBadSignature, "another context")
	require.ErrorIs(t, VerifySignature(pub, "made-up\n", []byte("body"), sig), ErrBadSignature)
	_, err = keys.Sign("made-up\n", []byte("body"))
	require.Error(t, err, "only the contract's contexts are signed")
}

func TestNothingPrintsAKey(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	secret, lk := newLink(t)
	page, engine, _ := handshake(t, keys, lk)
	raw, err := marshalKeyFile(keys)
	require.NoError(t, err)
	var f keyFile
	require.NoError(t, json.Unmarshal(raw, &f))
	signingB64 := strings.Trim(string(f.SigningKey), `"`)
	boxB64 := strings.Trim(string(f.BoxKey), `"`)

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("keys", "keys", keys, "link", lk, "session", page)
	printed := fmt.Sprintf("%v %+v %#v %s %v %+v %#v %v %+v %#v", keys, keys, keys, keys, lk, lk, lk.PSK, engine, page, page) + logged.String()
	for _, secretText := range []string{signingB64, boxB64, secret, hx(lk.PSK[:]), b64(lk.PSK[:])} {
		require.NotContains(t, printed, secretText)
	}
	require.Contains(t, printed, keys.EngineID())
}

// TestDeadTokensRunTheTagCheck: a token that is not live (unknown, or not
// SESSION_OPEN's) still goes through the tag check before it is refused, so
// it costs what a live token with a wrong psk costs; and a tag made under
// the zero psk the check uses for it is still refused.
func TestDeadTokensRunTheTagCheck(t *testing.T) {
	t.Parallel()
	lk := mustLink(t)
	other := mustLink(t)
	steps := func(m1 []byte, check HelloCheck) ([]string, error) {
		var got []string
		_, err := readHello(m1, check, func(step string) { got = append(got, step) })
		return got, err
	}
	want := []string{"header", "token", "tag"}

	_, unknown, err := WriteHello(TransportDirect, other)
	require.NoError(t, err)
	got, err := steps(unknown, HelloCheck{Transport: TransportDirect, Lookup: holding(lk)})
	require.ErrorIs(t, err, ErrLinkRefused)
	require.Equal(t, want, got, "an unknown token")

	_, held, err := WriteHello(TransportRelay, lk)
	require.NoError(t, err)
	got, err = steps(held, HelloCheck{Transport: TransportRelay, SessionToken: &other.Token, Lookup: holding(lk)})
	require.ErrorIs(t, err, ErrLinkRefused)
	require.Equal(t, want, got, "a token other than SESSION_OPEN's")

	_, wrongPSK, err := WriteHello(TransportRelay, LinkKeys{Token: lk.Token, PSK: other.PSK})
	require.NoError(t, err)
	got, err = steps(wrongPSK, relayCheck(lk))
	require.ErrorIs(t, err, ErrLinkRefused)
	require.Equal(t, want, got, "a live token with a wrong psk")

	_, zeroPSK, err := WriteHello(TransportDirect, LinkKeys{Token: other.Token})
	require.NoError(t, err)
	_, err = ReadHello(zeroPSK, HelloCheck{Transport: TransportDirect, Lookup: holding(lk)})
	require.ErrorIs(t, err, ErrLinkRefused, "a valid tag under the zero psk opens nothing")
}
