package vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// A hostile Vault written on the raw socket, for what the fake Vault will
// not send: malformed, out-of-place and oversized messages. Its script runs
// on the first socket only; every socket is then held open until the
// engine leaves.

type script func(ctx context.Context, ws *websocket.Conn) error

func hostileVault(t *testing.T, s script) (url string, result <-chan error) {
	t.Helper()
	out := make(chan error, 1)
	var sockets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		ws.SetReadLimit(1 << 20)
		if sockets.Add(1) == 1 {
			out <- s(r.Context(), ws)
		}
		// Hold the socket until the engine leaves.
		for {
			if _, _, err := ws.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://"), out
}

func writeText(ctx context.Context, ws *websocket.Conn, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageText, data)
}

func challenge() vaulttest.Challenge {
	return vaulttest.Challenge{Type: vaulttest.TypeChallenge, Challenge: strings.Repeat("A", 43)}
}

// ready runs CHALLENGE, AUTH and READY as an honest Vault would (without
// checking the signature: the fake Vault's tests do).
func ready(ctx context.Context, ws *websocket.Conn) error {
	if err := writeText(ctx, ws, challenge()); err != nil {
		return err
	}
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	var auth vaulttest.Auth
	if typ != websocket.MessageText || json.Unmarshal(data, &auth) != nil || auth.Type != vaulttest.TypeAuth || auth.Version != 1 {
		return fmt.Errorf("want AUTH, got %q", data)
	}
	return writeText(ctx, ws, vaulttest.Ready{Type: vaulttest.TypeReady})
}

// closedWith reads until the engine closes the socket and returns its code.
func closedWith(ctx context.Context, ws *websocket.Conn) websocket.StatusCode {
	ctx, cancel := context.WithTimeout(ctx, waitFor)
	defer cancel()
	for {
		if _, _, err := ws.Read(ctx); err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

// step is part of a hostile script.
type step = func(ctx context.Context, ws *websocket.Conn) error

// expectClose runs setup (when set), sends, and wants the engine to close
// the socket with code.
func expectClose(code channel.CloseError, setup, send step) script {
	return func(ctx context.Context, ws *websocket.Conn) error {
		if setup != nil {
			if err := setup(ctx, ws); err != nil {
				return err
			}
		}
		// Sent in the background: the engine may close before a large
		// message is all written.
		go func() { _ = send(ctx, ws) }()
		if got := closedWith(ctx, ws); got != websocket.StatusCode(code) {
			return fmt.Errorf("engine closed with %d, want %d %s", got, int(code), code.String())
		}
		return nil
	}
}

func binary(n int, head ...byte) func(ctx context.Context, ws *websocket.Conn) error {
	return func(ctx context.Context, ws *websocket.Conn) error {
		msg := make([]byte, n)
		copy(msg, head)
		return ws.Write(ctx, websocket.MessageBinary, msg)
	}
}

func text(s string) func(ctx context.Context, ws *websocket.Conn) error {
	return func(ctx context.Context, ws *websocket.Conn) error {
		return ws.Write(ctx, websocket.MessageText, []byte(s))
	}
}

// route is a ROUTE header for sid.
func route(sid vaulttest.SID) []byte { return vaulttest.Route(sid, nil) }

func TestRefusesAHostileVault(t *testing.T) {
	t.Parallel()
	maxRoute := channel.FrameMax + 18
	bigText := `{"type":"READY","x":"` + strings.Repeat("a", 4<<10) + `"}`
	cases := map[string]script{
		// Before READY the engine reads control messages only.
		"a control message over 4 KiB before READY": expectClose(channel.ErrTooLarge, nil, text(bigText)),
		"a binary message before READY":             expectClose(channel.ErrProtocol, nil, binary(32)),
		"READY before CHALLENGE":                    expectClose(channel.ErrProtocol, nil, text(`{"type":"READY"}`)),
		"a challenge that is not 32 bytes":          expectClose(channel.ErrProtocol, nil, text(`{"type":"CHALLENGE","challenge":"AAAA"}`)),
		"a challenge with an unknown field":         expectClose(channel.ErrProtocol, nil, text(`{"type":"CHALLENGE","challenge":"`+strings.Repeat("A", 43)+`","x":1}`)),
		"a challenge then junk":                     expectClose(channel.ErrProtocol, nil, text(`{"type":"CHALLENGE","challenge":"`+strings.Repeat("A", 43)+`"} {}`)),
		"no READY after AUTH": expectClose(channel.ErrProtocol, func(ctx context.Context, ws *websocket.Conn) error {
			if err := writeText(ctx, ws, challenge()); err != nil {
				return err
			}
			_, _, err := ws.Read(ctx)
			return err
		}, func(ctx context.Context, ws *websocket.Conn) error { return writeText(ctx, ws, challenge()) }),

		// After READY: sizes are checked before a message is read in.
		"a control message over 4 KiB":                   expectClose(channel.ErrTooLarge, ready, text(bigText)),
		"a ROUTE one byte over its limit":                expectClose(channel.ErrTooLarge, ready, binary(maxRoute+1, 0x01, 0x10)),
		"a 4 MiB ROUTE":                                  expectClose(channel.ErrTooLarge, ready, binary(4<<20, 0x01, 0x10)),
		"a ROUTE with version 2":                         expectClose(channel.ErrUnsupportedVersion, ready, binary(64, 0x02, 0x10)),
		"a binary message that is not ROUTE":             expectClose(channel.ErrProtocol, ready, binary(64, 0x01, 0x03)),
		"a ROUTE shorter than its header":                expectClose(channel.ErrProtocol, ready, binary(17, 0x01, 0x10)),
		"a second CHALLENGE":                             expectClose(channel.ErrProtocol, ready, text(`{"type":"CHALLENGE","challenge":"`+strings.Repeat("A", 43)+`"}`)),
		"a second READY":                                 expectClose(channel.ErrProtocol, ready, text(`{"type":"READY"}`)),
		"AUTH from the Vault":                            expectClose(channel.ErrProtocol, ready, text(`{"type":"AUTH","version":1,"sig":"x"}`)),
		"an unknown type":                                expectClose(channel.ErrProtocol, ready, text(`{"type":"PAIR"}`)),
		"not JSON":                                       expectClose(channel.ErrProtocol, ready, text(`READY`)),
		"SESSION_OPEN with a bad sid":                    expectClose(channel.ErrProtocol, ready, text(`{"type":"SESSION_OPEN","sid":"AAAA","linkToken":"`+strings.Repeat("A", 22)+`"}`)),
		"SESSION_CLOSE with a code outside the registry": expectClose(channel.ErrProtocol, ready, text(`{"type":"SESSION_CLOSE","sid":"`+strings.Repeat("A", 22)+`","code":1001}`)),
		"OK with a ref of 0":                             expectClose(channel.ErrProtocol, ready, text(`{"type":"OK","ref":0}`)),
		"ERROR with no code":                             expectClose(channel.ErrProtocol, ready, text(`{"type":"ERROR","ref":1}`)),
		"ERROR with a new code":                          expectClose(channel.ErrProtocol, ready, text(`{"type":"ERROR","code":"NOPE"}`)),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			url, result := hostileVault(t, s)
			c := newClient(t, fastOptions(url, newKeys(t)))
			run(t, c)
			select {
			case err := <-result:
				require.NoError(t, err)
			case <-time.After(waitFor):
				t.Fatal("the hostile Vault's script did not finish")
			}
		})
	}
}

// openSession sends SESSION_OPEN for sid.
func openSession(ctx context.Context, ws *websocket.Conn, sid vaulttest.SID) error {
	return writeText(ctx, ws, vaulttest.SessionOpen{Type: vaulttest.TypeSessionOpen, SID: sid.String(), LinkToken: strings.Repeat("A", 22)})
}

// sessionClosed reads the engine's next message: SESSION_CLOSE for sid with code.
func sessionClosed(ctx context.Context, ws *websocket.Conn, sid vaulttest.SID, code channel.CloseError) error {
	ctx, cancel := context.WithTimeout(ctx, waitFor)
	defer cancel()
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("want SESSION_CLOSE %s: %w", code.String(), err)
	}
	want := fmt.Sprintf(`{"type":"SESSION_CLOSE","sid":%q,"code":%d}`, sid.String(), code)
	if typ != websocket.MessageText || string(data) != want {
		return fmt.Errorf("got %s, want %s", data, want)
	}
	return nil
}

// hello is a message 1 of n bytes with the given version and type bytes.
func hello(sid vaulttest.SID, n int, version, typ byte) []byte {
	msg := make([]byte, n)
	if n >= 2 {
		msg[0], msg[1] = version, typ
	}
	return append(route(sid), msg...)
}

func sessionSteps(ctx context.Context, ws *websocket.Conn) error {
	type step struct {
		sid  vaulttest.SID
		msg  []byte
		want channel.CloseError
	}
	steps := []step{
		// A message 1 of the right size: the engine holds no link yet, so
		// it is refused as a dead token is.
		{vaulttest.SID{1}, hello(vaulttest.SID{1}, channel.Message1Len, 0x01, 0x01), channel.ErrLinkRefused},
		// Message 1 is exactly 99 bytes: the engine reads at most 100 and
		// drains the rest, so a frame-sized one costs no more memory.
		{vaulttest.SID{2}, hello(vaulttest.SID{2}, channel.Message1Len+1, 0x01, 0x01), channel.ErrProtocol},
		{vaulttest.SID{3}, hello(vaulttest.SID{3}, channel.FrameMax, 0x01, 0x01), channel.ErrProtocol},
		{vaulttest.SID{4}, hello(vaulttest.SID{4}, channel.Message1Len-1, 0x01, 0x01), channel.ErrProtocol},
		{vaulttest.SID{5}, hello(vaulttest.SID{5}, channel.Message1Len, 0x02, 0x01), channel.ErrUnsupportedVersion},
		{vaulttest.SID{6}, hello(vaulttest.SID{6}, channel.Message1Len, 0x01, 0x03), channel.ErrProtocol},
	}
	for _, s := range steps {
		if err := openSession(ctx, ws, s.sid); err != nil {
			return err
		}
		if err := ws.Write(ctx, websocket.MessageBinary, s.msg); err != nil {
			return err
		}
		if err := sessionClosed(ctx, ws, s.sid, s.want); err != nil {
			return err
		}
	}
	// Bytes for a session the engine does not hold, up to a frame: dropped,
	// and the socket stays.
	if err := ws.Write(ctx, websocket.MessageBinary, hello(vaulttest.SID{9}, channel.FrameMax, 0x01, 0x03)); err != nil {
		return err
	}
	// A sid opened twice is dropped.
	for range 2 {
		if err := openSession(ctx, ws, vaulttest.SID{7}); err != nil {
			return err
		}
	}
	if err := sessionClosed(ctx, ws, vaulttest.SID{7}, channel.ErrProtocol); err != nil {
		return err
	}
	// A forged SESSION_CLOSE for a session ends it at the engine.
	if err := openSession(ctx, ws, vaulttest.SID{8}); err != nil {
		return err
	}
	return writeText(ctx, ws, vaulttest.SessionClose{Type: vaulttest.TypeSessionClose, SID: vaulttest.SID{8}.String(), Code: int(vaulttest.CloseLinkUnknown)})
}

func TestSessionsAreRefusedWithinTheirPhaseLimit(t *testing.T) {
	t.Parallel()
	url, result := hostileVault(t, func(ctx context.Context, ws *websocket.Conn) error {
		if err := ready(ctx, ws); err != nil {
			return err
		}
		if err := sessionSteps(ctx, ws); err != nil {
			return err
		}
		// SID 8 was closed by the Vault, so its message 1 is dropped and
		// the next message the engine sends is about another session.
		if err := ws.Write(ctx, websocket.MessageBinary, hello(vaulttest.SID{8}, channel.Message1Len, 0x01, 0x01)); err != nil {
			return err
		}
		if err := openSession(ctx, ws, vaulttest.SID{10}); err != nil {
			return err
		}
		if err := ws.Write(ctx, websocket.MessageBinary, hello(vaulttest.SID{10}, 1, 0x01, 0x01)); err != nil {
			return err
		}
		return sessionClosed(ctx, ws, vaulttest.SID{10}, channel.ErrProtocol)
	})
	keys := newKeys(t)
	c := newClient(t, fastOptions(url, keys))
	run(t, c)
	require.NoError(t, <-result)
	require.Equal(t, vault.StateConnected, c.Status().State, "a refused session leaves the socket up")
}

func TestSessionLimitAndHandshakeTimeout(t *testing.T) {
	t.Parallel()
	// The handshake timeout is read from the client's clock when a
	// SESSION_OPEN arrives, so a test clock decides when sessions are late:
	// a slow runner cannot end the waiting sessions before the limit is
	// checked.
	clock := newTestClock()
	url, result := hostileVault(t, func(ctx context.Context, ws *websocket.Conn) error {
		if err := ready(ctx, ws); err != nil {
			return err
		}
		for i := range vault.MaxSessions {
			if err := openSession(ctx, ws, vaulttest.SID{byte(i), 1}); err != nil {
				return err
			}
		}
		over := vaulttest.SID{0xff}
		if err := openSession(ctx, ws, over); err != nil {
			return err
		}
		if err := sessionClosed(ctx, ws, over, channel.ErrSessionLimit); err != nil {
			return err
		}
		// Past the handshake timeout, the next SESSION_OPEN ends the waiting ones.
		clock.Advance(vault.HandshakeTimeout)
		if err := openSession(ctx, ws, vaulttest.SID{0xfe}); err != nil {
			return err
		}
		ended := map[string]bool{}
		for len(ended) < vault.MaxSessions {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return err
			}
			var m vaulttest.SessionClose
			if typ != websocket.MessageText || json.Unmarshal(data, &m) != nil || m.Code != int(vaulttest.CloseTimeout) {
				return fmt.Errorf("want SESSION_CLOSE TIMEOUT, got %s", data)
			}
			ended[m.SID] = true
		}
		return nil
	})
	opts := fastOptions(url, newKeys(t))
	opts.Now = clock.Now
	run(t, newClient(t, opts))
	require.NoError(t, <-result)
}

func TestStoppingClosesWithEngineShutdown(t *testing.T) {
	t.Parallel()
	readyDone := make(chan struct{})
	url, result := hostileVault(t, func(ctx context.Context, ws *websocket.Conn) error {
		if err := ready(ctx, ws); err != nil {
			return err
		}
		close(readyDone)
		if got := closedWith(ctx, ws); got != websocket.StatusCode(channel.ErrEngineShutdown) {
			return fmt.Errorf("engine closed with %d, want ENGINE_SHUTDOWN", got)
		}
		return nil
	})
	c := newClient(t, fastOptions(url, newKeys(t)))
	stop := run(t, c)
	<-readyDone
	require.Eventually(t, func() bool { return c.Status().State == vault.StateConnected }, waitFor, tick)
	require.NoError(t, stop())
	require.NoError(t, <-result)
}

func TestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	t.Cleanup(redirect.Close)

	c := newClient(t, fastOptions("ws://"+strings.TrimPrefix(redirect.URL, "http://"), newKeys(t)))
	run(t, c)
	require.Never(t, func() bool { return hits.Load() > 0 }, 100*time.Millisecond, tick)
	require.Equal(t, vault.StateConnecting, c.Status().State)
}

func TestLateMessageOneTimesOut(t *testing.T) {
	t.Parallel()
	// A session's wait for message 1 is measured on the client's clock, from
	// when its SESSION_OPEN is read to when its message 1 is. A test clock
	// sets that wait exactly: a slow runner can neither make the first
	// message 1 late nor read the second SESSION_OPEN after the wait began.
	clock := newTestClock()
	url, result := hostileVault(t, func(ctx context.Context, ws *websocket.Conn) error {
		if err := ready(ctx, ws); err != nil {
			return err
		}
		if err := openSession(ctx, ws, vaulttest.SID{1}); err != nil {
			return err
		}
		if err := openSession(ctx, ws, vaulttest.SID{2}); err != nil {
			return err
		}
		// In time: refused as a dead token is. The engine reads the socket in
		// order, so both SESSION_OPENs were read before this answer.
		if err := ws.Write(ctx, websocket.MessageBinary, hello(vaulttest.SID{1}, channel.Message1Len, 0x01, 0x01)); err != nil {
			return err
		}
		if err := sessionClosed(ctx, ws, vaulttest.SID{1}, channel.ErrLinkRefused); err != nil {
			return err
		}
		// At the handshake timeout, with no SESSION_OPEN in between: the
		// message 1 is not read, the session ends with TIMEOUT.
		clock.Advance(vault.HandshakeTimeout)
		if err := ws.Write(ctx, websocket.MessageBinary, hello(vaulttest.SID{2}, channel.Message1Len, 0x01, 0x01)); err != nil {
			return err
		}
		return sessionClosed(ctx, ws, vaulttest.SID{2}, channel.ErrTimeout)
	})
	opts := fastOptions(url, newKeys(t))
	opts.Now = clock.Now
	c := newClient(t, opts)
	run(t, c)
	require.NoError(t, <-result)
	require.Equal(t, vault.StateConnected, c.Status().State)
}
