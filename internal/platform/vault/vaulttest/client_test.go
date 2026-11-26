package vaulttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
)

// A minimal engine and page, written from the contract, to drive the fake.
// The real engine's dial-out comes with VC1-5.

const waitFor = 5 * time.Second

type engineKey struct {
	priv *ecdsa.PrivateKey
	spki string
	id   string
}

func newEngineKey(t *testing.T) engineKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return engineKey{priv: priv, spki: b64(der), id: EngineID(der)}
}

func (k engineKey) sign(t *testing.T, msg []byte) string {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	require.NoError(t, err)
	out := make([]byte, SigLen)
	r.FillBytes(out[:SigLen/2])
	s.FillBytes(out[SigLen/2:])
	return b64(out)
}

type testEngine struct {
	t    *testing.T
	key  engineKey
	conn *websocket.Conn
	ref  int64
}

// control is any control message, every field optional.
type control struct {
	Type      string          `json:"type"`
	Challenge string          `json:"challenge"`
	Ref       int64           `json:"ref"`
	Code      json.RawMessage `json:"code"`
	SID       string          `json:"sid"`
	LinkToken string          `json:"linkToken"`
}

func (c control) errCode() string {
	var s string
	_ = json.Unmarshal(c.Code, &s)
	return s
}

func (c control) closeCode() int {
	var n int
	_ = json.Unmarshal(c.Code, &n)
	return n
}

// dialRaw opens an engine socket with the given key header and returns the
// CHALLENGE, or the close code when the Vault closed instead.
func dialRaw(t *testing.T, v *Vault, engineID, keyHeader string) (*websocket.Conn, string, websocket.StatusCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	h := http.Header{}
	h.Set(EngineKeyHeader, keyHeader)
	conn, resp, err := websocket.Dial(ctx, v.EngineURL(engineID), &websocket.DialOptions{HTTPHeader: h})
	require.NoError(t, err)
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	conn.SetReadLimit(readLimit)
	t.Cleanup(func() { _ = conn.CloseNow() })
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return conn, "", websocket.CloseStatus(err)
	}
	require.Equal(t, websocket.MessageText, typ)
	var c Challenge
	require.NoError(t, strictjson.Decode(data, &c))
	require.Equal(t, TypeChallenge, c.Type)
	return conn, c.Challenge, 0
}

// dialEngine authenticates as key and waits for READY.
func dialEngine(t *testing.T, v *Vault, key engineKey) *testEngine {
	t.Helper()
	conn, challenge, _ := dialRaw(t, v, key.id, key.spki)
	e := &testEngine{t: t, key: key, conn: conn}
	e.send(Auth{Type: TypeAuth, Version: 1, Sig: key.sign(t, AuthInput(challenge, v.Host()))})
	require.Equal(t, TypeReady, e.control().Type)
	return e
}

func (e *testEngine) send(msg any) {
	e.t.Helper()
	data, err := json.Marshal(msg)
	require.NoError(e.t, err)
	e.write(websocket.MessageText, data)
}

func (e *testEngine) write(typ websocket.MessageType, data []byte) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	require.NoError(e.t, e.conn.Write(ctx, typ, data))
}

func (e *testEngine) read() (websocket.MessageType, []byte) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	typ, data, err := e.conn.Read(ctx)
	require.NoError(e.t, err)
	return typ, data
}

func (e *testEngine) control() control {
	e.t.Helper()
	typ, data := e.read()
	require.Equal(e.t, websocket.MessageText, typ, "want a control message, got %x", data)
	var c control
	require.NoError(e.t, json.Unmarshal(data, &c))
	return c
}

// route reads the next ROUTE message.
func (e *testEngine) route() (SID, []byte) {
	e.t.Helper()
	typ, data := e.read()
	require.Equal(e.t, websocket.MessageBinary, typ, "want a ROUTE, got %s", data)
	sid, payload, err := ParseRoute(data)
	require.NoError(e.t, err)
	return sid, payload
}

// register sends REGISTER_LINK and returns the answer.
func (e *testEngine) register(token string, expiresAt time.Time) control {
	e.t.Helper()
	e.ref++
	e.send(RegisterLink{Type: TypeRegisterLink, Ref: e.ref, LinkToken: token, ExpiresAt: expiresAt.UTC().Format(time.RFC3339)})
	c := e.control()
	require.Equal(e.t, e.ref, c.Ref)
	return c
}

func (e *testEngine) mustRegister(token string) {
	e.t.Helper()
	require.Equal(e.t, TypeOK, e.register(token, time.Now().Add(time.Hour)).Type)
}

func (e *testEngine) unregister(token string) control {
	e.t.Helper()
	e.ref++
	e.send(UnregisterLink{Type: TypeUnregisterLink, Ref: e.ref, LinkToken: token})
	return e.control()
}

// sessionOpen reads SESSION_OPEN and returns its sid.
func (e *testEngine) sessionOpen(token string) SID {
	e.t.Helper()
	c := e.control()
	require.Equal(e.t, TypeSessionOpen, c.Type)
	require.Equal(e.t, token, c.LinkToken)
	sid, err := ParseSID(c.SID)
	require.NoError(e.t, err)
	return sid
}

// closedWith reads until the socket closes and returns its close code.
func closedWith(t *testing.T, conn *websocket.Conn) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

func newToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, LinkTokenLen)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b64(b)
}

type testPage struct {
	t    *testing.T
	conn *websocket.Conn
}

func dialPage(t *testing.T, v *Vault, token, origin string) *testPage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	h := http.Header{}
	h.Set("Origin", origin)
	conn, resp, err := websocket.Dial(ctx, v.LinkURL(token), &websocket.DialOptions{HTTPHeader: h})
	require.NoError(t, err)
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	conn.SetReadLimit(readLimit)
	t.Cleanup(func() { _ = conn.CloseNow() })
	return &testPage{t: t, conn: conn}
}

func (p *testPage) send(data []byte) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	require.NoError(p.t, p.conn.Write(ctx, websocket.MessageBinary, data))
}

func (p *testPage) read() []byte {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	typ, data, err := p.conn.Read(ctx)
	require.NoError(p.t, err)
	require.Equal(p.t, websocket.MessageBinary, typ)
	return data
}

// pair connects an engine, registers a token and opens one page session.
func pair(t *testing.T, v *Vault) (*testEngine, *testPage, SID, string) {
	t.Helper()
	e := dialEngine(t, v, newEngineKey(t))
	token := newToken(t)
	e.mustRegister(token)
	p := dialPage(t, v, token, PortalOrigin)
	sid := e.sessionOpen(token)
	return e, p, sid, token
}
