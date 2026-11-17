package vaulttest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

func newVault(t *testing.T, opts Options) *Vault {
	t.Helper()
	v := New(opts)
	t.Cleanup(v.Close)
	return v
}

func TestEngineAuth(t *testing.T) {
	t.Run("a good signature gets READY", func(t *testing.T) {
		v := newVault(t, Options{})
		key := newEngineKey(t)
		dialEngine(t, v, key)
		require.Eventually(t, func() bool { return v.Connected(key.id) }, waitFor, time.Millisecond)
	})

	t.Run("challenges are fresh per socket", func(t *testing.T) {
		v := newVault(t, Options{})
		key := newEngineKey(t)
		_, c1, _ := dialRaw(t, v, key.id, key.spki)
		_, c2, _ := dialRaw(t, v, key.id, key.spki)
		require.Len(t, c1, 43)
		require.NotEqual(t, c1, c2)
	})

	refused := []struct {
		name string
		want websocket.StatusCode
		run  func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode
	}{
		{"a key header that is not an SPKI", CloseAuthFailed, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			_, _, code := dialRaw(t, v, key.id, "not-a-key")
			return code
		}},
		{"a key that does not hash to the path's id", CloseAuthFailed, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			_, _, code := dialRaw(t, v, newEngineKey(t).id, key.spki)
			return code
		}},
		{"a signature over another host", CloseAuthFailed, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, ch, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.send(Auth{Type: TypeAuth, Version: 1, Sig: key.sign(t, AuthInput(ch, "relay.basaltvault.app"))})
			return closedWith(t, conn)
		}},
		{"a signature over another challenge", CloseAuthFailed, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, _, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.send(Auth{Type: TypeAuth, Version: 1, Sig: key.sign(t, AuthInput(newToken(t), v.Host()))})
			return closedWith(t, conn)
		}},
		{"another engine's signature", CloseAuthFailed, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, ch, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.send(Auth{Type: TypeAuth, Version: 1, Sig: newEngineKey(t).sign(t, AuthInput(ch, v.Host()))})
			return closedWith(t, conn)
		}},
		{"AUTH version 2", CloseUnsupportedVersion, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, ch, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.send(Auth{Type: TypeAuth, Version: 2, Sig: key.sign(t, AuthInput(ch, v.Host()))})
			return closedWith(t, conn)
		}},
		{"a message other than AUTH", CloseProtocol, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, _, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.send(Ready{Type: TypeReady})
			return closedWith(t, conn)
		}},
		{"AUTH as binary", CloseProtocol, func(t *testing.T, v *Vault, key engineKey) websocket.StatusCode {
			conn, _, _ := dialRaw(t, v, key.id, key.spki)
			e := &testEngine{t: t, key: key, conn: conn}
			e.write(websocket.MessageBinary, []byte(`{"type":"AUTH"}`))
			return closedWith(t, conn)
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			v := newVault(t, Options{})
			key := newEngineKey(t)
			require.Equal(t, tc.want, tc.run(t, v, key))
			require.False(t, v.Connected(key.id))
		})
	}

	t.Run("a late AUTH", func(t *testing.T) {
		v := newVault(t, Options{ChallengeTTL: 50 * time.Millisecond})
		key := newEngineKey(t)
		conn, _, _ := dialRaw(t, v, key.id, key.spki)
		require.Equal(t, CloseAuthFailed, closedWith(t, conn))
	})
}

func TestEngineReplaced(t *testing.T) {
	v := newVault(t, Options{})
	key := newEngineKey(t)
	first := dialEngine(t, v, key)
	token := newToken(t)
	first.mustRegister(token)
	page := dialPage(t, v, token, PortalOrigin)
	first.sessionOpen(token)

	second := dialEngine(t, v, key)
	require.Equal(t, CloseReplaced, closedWith(t, first.conn))
	require.Equal(t, CloseEngineOffline, closedWith(t, page.conn))

	// The binding outlives the socket: the new socket registers again and serves.
	second.mustRegister(token)
	dialPage(t, v, token, PortalOrigin)
	second.sessionOpen(token)
}

func TestRegisterLink(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	t.Run("binds a token to the engine that registered it", func(t *testing.T) {
		v := newVault(t, Options{Now: clock})
		a := dialEngine(t, v, newEngineKey(t))
		b := dialEngine(t, v, newEngineKey(t))
		token := newToken(t)

		require.Equal(t, TypeOK, a.register(token, now.Add(time.Hour)).Type)
		require.Equal(t, TypeOK, a.register(token, now.Add(2*time.Hour)).Type, "idempotent for the same engine")

		c := b.register(token, now.Add(time.Hour))
		require.Equal(t, TypeError, c.Type)
		require.Equal(t, ErrLinkConflict, c.errCode())

		c = b.unregister(token)
		require.Equal(t, ErrLinkConflict, c.errCode(), "another engine cannot unregister it")
		owner, ok := v.LinkOwner(token)
		require.True(t, ok)
		require.Equal(t, a.key.id, owner)

		require.Equal(t, TypeOK, a.unregister(token).Type)
		require.Equal(t, TypeOK, b.register(token, now.Add(time.Hour)).Type, "free after UNREGISTER_LINK")
		require.Equal(t, TypeOK, a.unregister(newToken(t)).Type, "an unknown token answers OK")
	})

	t.Run("the binding holds while its engine is offline", func(t *testing.T) {
		v := newVault(t, Options{Now: clock})
		a := dialEngine(t, v, newEngineKey(t))
		b := dialEngine(t, v, newEngineKey(t))
		token := newToken(t)
		a.mustRegister(token)
		v.DisconnectEngine(a.key.id, CloseNormal)
		require.Equal(t, ErrLinkConflict, b.register(token, now.Add(time.Hour)).errCode())
	})

	t.Run("a token is dropped at its expiry", func(t *testing.T) {
		var mu sync.Mutex
		at := now
		v := newVault(t, Options{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return at }})
		a := dialEngine(t, v, newEngineKey(t))
		b := dialEngine(t, v, newEngineKey(t))
		token := newToken(t)
		require.Equal(t, TypeOK, a.register(token, now.Add(time.Minute)).Type)

		mu.Lock()
		at = now.Add(time.Minute)
		mu.Unlock()
		_, ok := v.LinkOwner(token)
		require.False(t, ok)
		page := dialPage(t, v, token, PortalOrigin)
		require.Equal(t, CloseLinkUnknown, closedWith(t, page.conn))
		require.Equal(t, TypeOK, b.register(token, at.Add(time.Hour)).Type)
	})

	t.Run("expiry in the past or too far ahead", func(t *testing.T) {
		v := newVault(t, Options{Now: clock})
		a := dialEngine(t, v, newEngineKey(t))
		require.Equal(t, ErrInvalidExpiry, a.register(newToken(t), now.Add(-time.Second)).errCode())
		require.Equal(t, ErrInvalidExpiry, a.register(newToken(t), now.Add(MaxExpiryAhead+time.Second)).errCode())
		require.Equal(t, TypeOK, a.register(newToken(t), now.Add(MaxExpiryAhead)).Type)
	})

	t.Run("live links per engine", func(t *testing.T) {
		v := newVault(t, Options{Now: clock, MaxLinksPerEngine: 1})
		a := dialEngine(t, v, newEngineKey(t))
		a.register(newToken(t), now.Add(time.Hour))
		require.Equal(t, ErrLinkLimit, a.register(newToken(t), now.Add(time.Hour)).errCode())
	})
}

func TestPageSocket(t *testing.T) {
	t.Run("a foreign Origin", func(t *testing.T) {
		v := newVault(t, Options{})
		e := dialEngine(t, v, newEngineKey(t))
		token := newToken(t)
		e.mustRegister(token)
		page := dialPage(t, v, token, "https://evil.example")
		require.Equal(t, CloseProtocol, closedWith(t, page.conn))
	})

	t.Run("a token nobody registered", func(t *testing.T) {
		v := newVault(t, Options{})
		page := dialPage(t, v, newToken(t), PortalOrigin)
		require.Equal(t, CloseLinkUnknown, closedWith(t, page.conn))
	})

	t.Run("an engine with no socket", func(t *testing.T) {
		v := newVault(t, Options{})
		e := dialEngine(t, v, newEngineKey(t))
		token := newToken(t)
		e.mustRegister(token)
		v.DisconnectEngine(e.key.id, CloseNormal)
		page := dialPage(t, v, token, PortalOrigin)
		require.Equal(t, CloseEngineOffline, closedWith(t, page.conn))
	})

	t.Run("forwards bytes unchanged and in order both ways", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, sid, _ := pair(t, v)
		const n = 50
		for i := range n {
			page.send(bytes.Repeat([]byte{byte(i)}, i+1))
		}
		for i := range n {
			got, payload := e.route()
			require.Equal(t, sid, got)
			require.Equal(t, bytes.Repeat([]byte{byte(i)}, i+1), payload)
		}
		for i := range n {
			e.write(websocket.MessageBinary, Route(sid, []byte{byte(i), 0xff}))
		}
		for i := range n {
			require.Equal(t, []byte{byte(i), 0xff}, page.read())
		}
	})

	t.Run("carries the largest messages", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, sid, _ := pair(t, v)
		big := bytes.Repeat([]byte{0xab}, MaxFrame)
		page.send(big)
		_, got := e.route()
		require.Equal(t, big, got)
		e.write(websocket.MessageBinary, Route(sid, big))
		require.Equal(t, big, page.read())
	})

	t.Run("the page ends the session", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, sid, _ := pair(t, v)
		require.NoError(t, page.conn.Close(CloseHandshakeFailed, "HANDSHAKE_FAILED"))
		c := e.control()
		require.Equal(t, TypeSessionClose, c.Type)
		require.Equal(t, sid.String(), c.SID)
		require.Equal(t, int(CloseHandshakeFailed), c.closeCode())
		require.Empty(t, v.Sessions())
	})

	t.Run("a page that leaves with a code outside the registry is reported as 1000", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, _, _ := pair(t, v)
		require.NoError(t, page.conn.Close(websocket.StatusGoingAway, ""))
		require.Equal(t, int(CloseNormal), e.control().closeCode())
	})

	t.Run("the engine ends the session", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, sid, _ := pair(t, v)
		e.send(SessionClose{Type: TypeSessionClose, SID: sid.String(), Code: int(CloseLinkRefused)})
		require.Equal(t, CloseLinkRefused, closedWith(t, page.conn))
	})

	t.Run("UNREGISTER_LINK closes its pages", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, _, token := pair(t, v)
		require.Equal(t, TypeOK, e.unregister(token).Type)
		require.Equal(t, CloseLinkUnknown, closedWith(t, page.conn))
	})

	t.Run("an engine that drops closes its pages", func(t *testing.T) {
		v := newVault(t, Options{})
		e, page, _, _ := pair(t, v)
		_ = e.conn.CloseNow()
		require.Equal(t, CloseEngineOffline, closedWith(t, page.conn))
	})

	pageRefusals := []struct {
		name string
		typ  websocket.MessageType
		data []byte
		want websocket.StatusCode
	}{
		{"a text message", websocket.MessageText, []byte("hello"), CloseProtocol},
		{"a message over the frame limit", websocket.MessageBinary, make([]byte, MaxFrame+1), CloseTooLarge},
	}
	for _, tc := range pageRefusals {
		t.Run(tc.name, func(t *testing.T) {
			v := newVault(t, Options{})
			e, page, sid, _ := pair(t, v)
			require.NoError(t, page.conn.Write(t.Context(), tc.typ, tc.data))
			require.Equal(t, tc.want, closedWith(t, page.conn))
			c := e.control()
			require.Equal(t, TypeSessionClose, c.Type)
			require.Equal(t, sid.String(), c.SID)
			require.Equal(t, int(tc.want), c.closeCode())
		})
	}

	t.Run("session limits", func(t *testing.T) {
		v := newVault(t, Options{MaxSessionsPerLink: 1})
		e, _, _, token := pair(t, v)
		second := dialPage(t, v, token, PortalOrigin)
		require.Equal(t, CloseSessionLimit, closedWith(t, second.conn))
		other := newToken(t)
		e.mustRegister(other)
		dialPage(t, v, other, PortalOrigin)
		e.sessionOpen(other)
	})
}

func TestSessionsKeptApart(t *testing.T) {
	v := newVault(t, Options{})
	a, pageA, sidA, _ := pair(t, v)
	b, _, sidB, _ := pair(t, v)

	b.write(websocket.MessageBinary, Route(sidA, []byte("not yours")))
	c := b.control()
	require.Equal(t, TypeError, c.Type)
	require.Equal(t, ErrUnknownSession, c.errCode())

	b.send(SessionClose{Type: TypeSessionClose, SID: sidA.String(), Code: int(CloseNormal)})
	require.Equal(t, ErrUnknownSession, b.control().errCode())

	// A's session is untouched: its next message is A's own.
	a.write(websocket.MessageBinary, Route(sidA, []byte("mine")))
	require.Equal(t, []byte("mine"), pageA.read())
	require.NotEqual(t, sidA, sidB)
}

func TestEngineSocketRefusals(t *testing.T) {
	cases := []struct {
		name string
		typ  websocket.MessageType
		data func(e *testEngine) []byte
		want websocket.StatusCode
	}{
		{"a control message over 4 KiB", websocket.MessageText, func(*testEngine) []byte {
			return append([]byte(`{"type":"READY","x":"`), bytes.Repeat([]byte("a"), MaxControl)...)
		}, CloseTooLarge},
		{"a ROUTE over its limit", websocket.MessageBinary, func(*testEngine) []byte {
			return Route(SID{}, make([]byte, MaxFrame+1))
		}, CloseTooLarge},
		{"a ROUTE with version 2", websocket.MessageBinary, func(*testEngine) []byte {
			return append([]byte{0x02, TypeRoute}, make([]byte, SIDLen)...)
		}, CloseUnsupportedVersion},
		{"a binary message of another type", websocket.MessageBinary, func(*testEngine) []byte {
			return append([]byte{Version, 0x03}, make([]byte, SIDLen)...)
		}, CloseProtocol},
		{"a short ROUTE", websocket.MessageBinary, func(*testEngine) []byte { return []byte{Version, TypeRoute} }, CloseProtocol},
		{"text that is not JSON", websocket.MessageText, func(*testEngine) []byte { return []byte("{") }, CloseProtocol},
		{"an unknown type", websocket.MessageText, func(*testEngine) []byte { return []byte(`{"type":"HELLO"}`) }, CloseProtocol},
		{"a Vault-only type", websocket.MessageText, func(*testEngine) []byte { return []byte(`{"type":"OK","ref":1}`) }, CloseProtocol},
		{"an unknown field", websocket.MessageText, func(e *testEngine) []byte {
			return []byte(`{"type":"REGISTER_LINK","ref":1,"linkToken":"` + newToken(e.t) + `","expiresAt":"2099-01-01T00:00:00Z","x":1}`)
		}, CloseProtocol},
		{"ref 0", websocket.MessageText, func(e *testEngine) []byte {
			return []byte(`{"type":"UNREGISTER_LINK","ref":0,"linkToken":"` + newToken(e.t) + `"}`)
		}, CloseProtocol},
		{"a bad link token", websocket.MessageText, func(*testEngine) []byte {
			return []byte(`{"type":"UNREGISTER_LINK","ref":1,"linkToken":"short"}`)
		}, CloseProtocol},
		{"SESSION_CLOSE with a code outside the registry", websocket.MessageText, func(*testEngine) []byte {
			return []byte(`{"type":"SESSION_CLOSE","sid":"` + SID{}.String() + `","code":1001}`)
		}, CloseProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVault(t, Options{})
			e := dialEngine(t, v, newEngineKey(t))
			e.write(tc.typ, tc.data(e))
			require.Equal(t, tc.want, closedWith(t, e.conn))
		})
	}
}

func TestCloseCodesMatchRegistry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "mcp", "vault", "close-codes.json"))
	require.NoError(t, err)
	var reg struct {
		Codes []struct {
			Code   int      `json:"code"`
			Name   string   `json:"name"`
			SentBy []string `json:"sentBy"`
		} `json:"codes"`
	}
	require.NoError(t, json.Unmarshal(data, &reg))
	want := map[int]string{}
	fromEngine := map[int]bool{int(CloseNormal): true}
	for _, c := range reg.Codes {
		want[c.Code] = c.Name
		for _, by := range c.SentBy {
			if by == "ENGINE" {
				fromEngine[c.Code] = true
			}
		}
	}
	require.Equal(t, want, CloseNames)
	require.Equal(t, fromEngine, engineCloseCodes)
}

func TestEngineSessionCloseRefusesCodesItDoesNotSend(t *testing.T) {
	for _, code := range []websocket.StatusCode{CloseAuthFailed, CloseReplaced, CloseLinkUnknown, CloseEngineOffline, CloseHandshakeFailed} {
		t.Run(CloseNames[int(code)], func(t *testing.T) {
			v := newVault(t, Options{})
			e, _, sid, _ := pair(t, v)
			e.send(SessionClose{Type: TypeSessionClose, SID: sid.String(), Code: int(code)})
			require.Equal(t, CloseProtocol, closedWith(t, e.conn))
		})
	}
}

func TestOnUnregister(t *testing.T) {
	var verdict atomic.Value
	v := newVault(t, Options{OnUnregister: func(string, UnregisterLink) Verdict { return verdict.Load().(Verdict) }})
	e, page, sid, token := pair(t, v)

	verdict.Store(Verdict{ForceOK: true})
	require.Equal(t, TypeOK, e.unregister(token).Type)
	owner, ok := v.LinkOwner(token)
	require.True(t, ok, "a forged OK unbinds nothing")
	require.Equal(t, e.key.id, owner)

	verdict.Store(Verdict{Code: ErrLinkConflict})
	require.Equal(t, ErrLinkConflict, e.unregister(token).errCode())

	verdict.Store(Verdict{Drop: true})
	e.ref++
	e.send(UnregisterLink{Type: TypeUnregisterLink, Ref: e.ref, LinkToken: token})
	require.NoError(t, v.InjectControl(e.key.id, Ready{Type: TypeReady}))
	require.Equal(t, TypeReady, e.control().Type, "no answer came before the marker")

	// The page was never closed: it still gets the engine's bytes.
	e.write(websocket.MessageBinary, Route(sid, []byte("still here")))
	require.Equal(t, []byte("still here"), page.read())
}

func TestOnSessionClose(t *testing.T) {
	t.Run("drop the engine's close: the page stays open", func(t *testing.T) {
		v := newVault(t, Options{OnSessionClose: func(_ SessionInfo, dir Direction, code websocket.StatusCode) (websocket.StatusCode, bool) {
			return code, dir != ToPage
		}})
		e, page, sid, _ := pair(t, v)
		e.send(SessionClose{Type: TypeSessionClose, SID: sid.String(), Code: int(CloseLinkRefused)})
		e.write(websocket.MessageBinary, Route(sid, []byte("after close")))
		require.Equal(t, []byte("after close"), page.read())
	})

	t.Run("alter the engine's code", func(t *testing.T) {
		v := newVault(t, Options{OnSessionClose: func(SessionInfo, Direction, websocket.StatusCode) (websocket.StatusCode, bool) {
			return CloseTimeout, true
		}})
		e, page, sid, _ := pair(t, v)
		e.send(SessionClose{Type: TypeSessionClose, SID: sid.String(), Code: int(CloseLinkRefused)})
		require.Equal(t, CloseTimeout, closedWith(t, page.conn))
	})

	t.Run("drop the page's close: the engine is not told", func(t *testing.T) {
		seen := make(chan Direction, 1)
		v := newVault(t, Options{OnSessionClose: func(_ SessionInfo, dir Direction, code websocket.StatusCode) (websocket.StatusCode, bool) {
			seen <- dir
			return code, false
		}})
		e, page, _, _ := pair(t, v)
		require.NoError(t, page.conn.Close(CloseNormal, ""))
		require.Equal(t, ToEngine, <-seen)
		require.NoError(t, v.InjectControl(e.key.id, Ready{Type: TypeReady}))
		require.Equal(t, TypeReady, e.control().Type, "no SESSION_CLOSE came before the marker")
	})
}

func TestSuppressPongs(t *testing.T) {
	v := newVault(t, Options{})
	e := dialEngine(t, v, newEngineKey(t))
	// Ping needs a reader; nothing but pongs arrives after READY.
	go func() { _, _, _ = e.conn.Read(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	require.NoError(t, e.conn.Ping(ctx))

	v.SuppressPongs(e.key.id, true)
	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelShort()
	require.Error(t, e.conn.Ping(short), "no pong while suppressed")
	require.Equal(t, 2, v.Pings(e.key.id))
}

func TestCloseEndsEverything(t *testing.T) {
	before := runtime.NumGoroutine()
	v := New(Options{})
	e, page, _, _ := pair(t, v)
	key := newEngineKey(t)
	midAuth, _, _ := dialRaw(t, v, key.id, key.spki) // never answers CHALLENGE

	start := time.Now()
	v.Close()
	require.Less(t, time.Since(start), 10*time.Second, "Close does not wait out the 30-second CHALLENGE")
	for _, conn := range []*websocket.Conn{e.conn, page.conn, midAuth} {
		_ = conn.CloseNow()
	}
	if !assertEventuallyFewer(before) {
		buf := make([]byte, 1<<20)
		t.Fatalf("goroutines left: %d, before: %d\n%s", runtime.NumGoroutine(), before, buf[:runtime.Stack(buf, true)])
	}
}

// --- hostile hooks ---

func TestTamper(t *testing.T) {
	t.Run("drop", func(t *testing.T) {
		v := newVault(t, Options{Tamper: func(m Message) []Delivery {
			if bytes.Equal(m.Data, []byte("drop me")) {
				return nil
			}
			return []Delivery{Forward(m)}
		}})
		e, page, _, _ := pair(t, v)
		page.send([]byte("drop me"))
		page.send([]byte("keep"))
		_, got := e.route()
		require.Equal(t, []byte("keep"), got)
	})

	t.Run("replay", func(t *testing.T) {
		v := newVault(t, Options{Tamper: func(m Message) []Delivery { return []Delivery{Forward(m), Forward(m)} }})
		e, page, _, _ := pair(t, v)
		page.send([]byte("once"))
		_, first := e.route()
		_, second := e.route()
		require.Equal(t, first, second)
	})

	t.Run("reorder", func(t *testing.T) {
		var mu sync.Mutex
		var held *Message
		v := newVault(t, Options{Tamper: func(m Message) []Delivery {
			mu.Lock()
			defer mu.Unlock()
			if held == nil {
				held = &m
				return nil
			}
			out := []Delivery{Forward(m), Forward(*held)}
			held = nil
			return out
		}})
		e, page, _, _ := pair(t, v)
		page.send([]byte("1"))
		page.send([]byte("2"))
		_, a := e.route()
		_, b := e.route()
		require.Equal(t, []byte("2"), a)
		require.Equal(t, []byte("1"), b)
	})

	t.Run("reflect", func(t *testing.T) {
		v := newVault(t, Options{Tamper: func(m Message) []Delivery {
			d := Forward(m)
			d.Dir = ToPage
			return []Delivery{d}
		}})
		_, page, _, _ := pair(t, v)
		page.send([]byte("echo"))
		require.Equal(t, []byte("echo"), page.read())
	})

	t.Run("splice into another session", func(t *testing.T) {
		var target atomic.Pointer[SID]
		v := newVault(t, Options{Tamper: func(m Message) []Delivery {
			d := Forward(m)
			if to := target.Load(); to != nil && m.Session.SID != *to {
				d.SID = *to
			}
			return []Delivery{d}
		}})
		e, pageA, _, token := pair(t, v)
		dialPage(t, v, token, PortalOrigin)
		sidB := e.sessionOpen(token)
		target.Store(&sidB)
		pageA.send([]byte("from A"))
		got, payload := e.route()
		require.Equal(t, sidB, got)
		require.Equal(t, []byte("from A"), payload)
	})

	t.Run("sees engine messages too", func(t *testing.T) {
		seen := make(chan Message, 1)
		v := newVault(t, Options{Tamper: func(m Message) []Delivery {
			if m.Dir == ToPage {
				seen <- m
			}
			return []Delivery{Forward(m)}
		}})
		e, page, sid, token := pair(t, v)
		e.write(websocket.MessageBinary, Route(sid, []byte("hi")))
		require.Equal(t, []byte("hi"), page.read())
		m := <-seen
		require.Equal(t, SessionInfo{SID: sid, LinkToken: token, EngineID: e.key.id}, m.Session)
	})
}

func TestInject(t *testing.T) {
	v := newVault(t, Options{})
	e, page, sid, token := pair(t, v)

	require.NoError(t, v.Inject(Delivery{SID: sid, Dir: ToEngine, Data: []byte("forged")}))
	got, payload := e.route()
	require.Equal(t, sid, got)
	require.Equal(t, []byte("forged"), payload)

	require.NoError(t, v.Inject(Delivery{SID: sid, Dir: ToPage, Data: []byte("forged")}))
	require.Equal(t, []byte("forged"), page.read())

	require.ErrorIs(t, v.Inject(Delivery{SID: SID{1}, Dir: ToPage}), ErrNoSession)

	fake := SID{9}
	require.NoError(t, v.InjectControl(e.key.id, SessionOpen{Type: TypeSessionOpen, SID: fake.String(), LinkToken: token}))
	require.Equal(t, fake, e.sessionOpen(token))
	require.NoError(t, v.InjectControl(e.key.id, OK{Type: TypeOK, Ref: 77}))
	require.Equal(t, int64(77), e.control().Ref)
	require.NoError(t, v.InjectRaw(e.key.id, websocket.MessageBinary, Route(fake, []byte("junk"))))
	got, _ = e.route()
	require.Equal(t, fake, got)
	require.ErrorIs(t, v.InjectControl("nobody", OK{}), ErrNoEngine)

	require.NoError(t, v.CloseSession(sid, CloseTimeout))
	require.Equal(t, CloseTimeout, closedWith(t, page.conn))
	c := e.control()
	require.Equal(t, TypeSessionClose, c.Type)
	require.Equal(t, int(CloseTimeout), c.closeCode())
}

func TestLoseStateLetsARivalRegisterFirst(t *testing.T) {
	v := newVault(t, Options{})
	honest := dialEngine(t, v, newEngineKey(t))
	rival := dialEngine(t, v, newEngineKey(t))
	token := newToken(t)
	honest.mustRegister(token)

	v.LoseState()
	_, ok := v.LinkOwner(token)
	require.False(t, ok)
	rival.mustRegister(token)
	require.Equal(t, ErrLinkConflict, honest.register(token, time.Now().Add(time.Hour)).errCode())

	dialPage(t, v, token, PortalOrigin)
	rival.sessionOpen(token)
}

func TestOnRegisterRace(t *testing.T) {
	honestKey, rivalKey := newEngineKey(t), newEngineKey(t)
	release := make(chan struct{})
	held := make(chan struct{})
	v := newVault(t, Options{OnRegister: func(engineID string, _ RegisterLink) Verdict {
		if engineID == honestKey.id {
			close(held)
			<-release
		}
		return Verdict{}
	}})
	honest := dialEngine(t, v, honestKey)
	rival := dialEngine(t, v, rivalKey)
	token := newToken(t)

	honest.ref++
	honest.send(RegisterLink{Type: TypeRegisterLink, Ref: honest.ref, LinkToken: token, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	<-held
	rival.mustRegister(token)
	close(release)
	require.Equal(t, ErrLinkConflict, honest.control().errCode())
}

func TestOnRegisterVerdicts(t *testing.T) {
	var verdict atomic.Value
	v := newVault(t, Options{OnRegister: func(string, RegisterLink) Verdict { return verdict.Load().(Verdict) }})
	e := dialEngine(t, v, newEngineKey(t))
	token := newToken(t)

	verdict.Store(Verdict{ForceOK: true})
	e.mustRegister(token)
	_, ok := v.LinkOwner(token)
	require.False(t, ok, "a forged OK binds nothing")

	verdict.Store(Verdict{Code: ErrRateLimited})
	require.Equal(t, ErrRateLimited, e.register(token, time.Now().Add(time.Hour)).errCode())

	verdict.Store(Verdict{Drop: true})
	e.ref++
	e.send(RegisterLink{Type: TypeRegisterLink, Ref: e.ref, LinkToken: token, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	require.NoError(t, v.InjectControl(e.key.id, Ready{Type: TypeReady}))
	require.Equal(t, TypeReady, e.control().Type, "no answer came before the marker")
}

func TestBindRoutesATokenToAnyEngine(t *testing.T) {
	v := newVault(t, Options{})
	owner := dialEngine(t, v, newEngineKey(t))
	other := dialEngine(t, v, newEngineKey(t))
	token := newToken(t)
	owner.mustRegister(token)

	v.Bind(token, other.key.id, time.Now().Add(time.Hour))
	dialPage(t, v, token, PortalOrigin)
	other.sessionOpen(token)
}

func TestChallengeOption(t *testing.T) {
	fixed := [ChallengeLen]byte{1, 2, 3}
	v := newVault(t, Options{Challenge: func() [ChallengeLen]byte { return fixed }})
	key := newEngineKey(t)
	_, c1, _ := dialRaw(t, v, key.id, key.spki)
	_, c2, _ := dialRaw(t, v, key.id, key.spki)
	require.Equal(t, b64(fixed[:]), c1)
	require.Equal(t, c1, c2)
}

func assertEventuallyFewer(n int) bool {
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
