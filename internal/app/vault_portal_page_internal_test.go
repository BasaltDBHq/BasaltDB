package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/pages"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault/vaulttest"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// portalStep is one line testdata/portal_relay.mjs prints.
type portalStep struct {
	Step   string `json:"step"`
	URL    string `json:"url"`
	Engine struct {
		EngineID    string `json:"engineId"`
		Fingerprint string `json:"fingerprint"`
	} `json:"engine"`
	Status        int    `json:"status"`
	Type          string `json:"type"`
	Body          string `json:"body"`
	Name          string `json:"name"`
	Code          string `json:"code"`
	Reason        string `json:"reason"`
	PersonMessage string `json:"personMessage"`
}

// runPortalPage runs the portal's RELAY transport (web/lib/relay.js and
// channel.js, under node) through the fake Vault of s, reading path gets
// times with s's link, and returns its steps by name.
func runPortalPage(t *testing.T, s *vaultSession, path string, gets int) map[string]portalStep {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; make web-check needs it too")
	}
	arg, err := json.Marshal(map[string]any{"secret": s.secret, "path": path, "gets": gets})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "testdata/portal_relay.mjs", s.v.URL(), string(arg))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	steps := map[string]portalStep{}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	for sc.Scan() {
		var st portalStep
		require.NoError(t, json.Unmarshal(sc.Bytes(), &st), sc.Text())
		_, seen := steps[st.Step]
		require.False(t, seen, "step %s twice", st.Step)
		steps[st.Step] = st
	}
	return steps
}

// withoutNonce is a request's JSON without revealNonce, which the engine
// makes fresh for every read.
func withoutNonce(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &m), body)
	require.Contains(t, m, "revealNonce")
	delete(m, "revealNonce")
	return m
}

// The portal's own page code opens a relay session to a real engine on
// real Postgres through the fake Vault: the handshake completes, the page
// shows the fingerprint of the key it verified, and the approval it reads
// is the JSON the engine serves on loopback. The socket path carries the
// link token only, and neither the link secret, its psk nor the item id
// crosses the Vault.
func TestPortalChannelClientAgainstFakeVault(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	w := &wire{}
	s := serveOverVault(t, w, e.svc, e.secrets, e.held)
	path := "/api/v1/approvals/" + e.held.String()

	loopback := pages.New(links.Portal, slog.New(slog.DiscardHandler))
	loopback.Add(e.svc)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	for k, v := range pagetest.Headers(s.secret) {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	loopback.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	steps := runPortalPage(t, s, path, 1)
	require.NotContains(t, steps, "error", steps["error"])

	require.Equal(t, "wss://relay.basaltvault.app/v1/links/"+s.keys.Token.Wire(), steps["socket"].URL)

	engineID, ok := s.v.LinkOwner(s.keys.Token.Wire())
	require.True(t, ok)
	require.Equal(t, engineID, steps["open"].Engine.EngineID, "the engine the session verified")
	require.Equal(t, channel.FingerprintOf(engineID), steps["open"].Engine.Fingerprint)
	require.Regexp(t, `^\S{4} \S{4} \S{4} \S{4}$`, steps["open"].Engine.Fingerprint)

	got := steps["get1"]
	require.Equal(t, http.StatusOK, got.Status, got.Body)
	require.Equal(t, "application/json", got.Type)
	require.Equal(t, withoutNonce(t, rec.Body.String()), withoutNonce(t, got.Body), "the same approval as on loopback")

	w.mu.Lock()
	defer w.mu.Unlock()
	secrets := []string{
		s.secret, e.held.String(), links.SecretHeader,
		base64.RawURLEncoding.EncodeToString(s.keys.PSK[:]), string(s.keys.PSK[:]),
	}
	require.NotEmpty(t, w.session)
	for _, m := range w.session {
		for _, secret := range secrets {
			require.False(t, bytes.Contains(m.Data, []byte(secret)), "%q crossed the Vault in the clear", secret)
		}
	}
	for _, m := range w.engine {
		for _, secret := range secrets {
			require.False(t, bytes.Contains(m, []byte(secret)), "%q crossed the engine's socket in the clear", secret)
		}
	}
}

// hostileWire is a wire whose Vault alters the session: edit decides what
// is delivered for each message, by its index among those of its direction.
type hostileWire struct {
	mu   sync.Mutex
	seen map[vaulttest.Direction]int
	edit func(m vaulttest.Message, n int, kept []vaulttest.Message) []vaulttest.Delivery
	kept []vaulttest.Message
	// closes are the codes the page closed its socket with, as the Vault
	// tells the engine.
	closes []websocket.StatusCode
}

func (h *hostileWire) onClose(_ vaulttest.SessionInfo, dir vaulttest.Direction, code websocket.StatusCode) (websocket.StatusCode, bool) {
	if dir == vaulttest.ToEngine {
		h.mu.Lock()
		h.closes = append(h.closes, code)
		h.mu.Unlock()
	}
	return code, true
}

func (h *hostileWire) closedWith(code websocket.StatusCode) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Contains(h.closes, code)
}

func (h *hostileWire) tamper(m vaulttest.Message) []vaulttest.Delivery {
	h.mu.Lock()
	defer h.mu.Unlock()
	m.Data = slices.Clone(m.Data)
	n := h.seen[m.Dir]
	h.seen[m.Dir]++
	out := h.edit(m, n, h.kept)
	h.kept = append(h.kept, m)
	return out
}

// flip is m delivered with one byte of its ciphertext changed.
func flip(m vaulttest.Message) []vaulttest.Delivery {
	d := vaulttest.Forward(m)
	d.Data[len(d.Data)-1] ^= 0x01
	return []vaulttest.Delivery{d}
}

// A Vault that alters the session makes the page stop and show nothing
// from the engine: a changed message 2 fails the handshake, and a frame
// that is tampered, replayed or reflected closes the session with
// FRAME_INVALID (4008; a bad message 2, HANDSHAKE_FAILED, 4007) before the
// page reads anything from it.
func TestPortalChannelClientRefusesAHostileVault(t *testing.T) {
	t.Parallel()
	forward := func(m vaulttest.Message) []vaulttest.Delivery { return []vaulttest.Delivery{vaulttest.Forward(m)} }
	cases := map[string]struct {
		gets int
		edit func(m vaulttest.Message, n int, kept []vaulttest.Message) []vaulttest.Delivery
		// at is the step that fails; the steps before it went through.
		at   string
		code string
		// close is the code the page closes its socket with.
		close websocket.StatusCode
	}{
		"a changed message 2": {gets: 1, at: "open", code: "UNAVAILABLE", close: 4007, edit: func(m vaulttest.Message, n int, _ []vaulttest.Message) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToPage && n == 0 {
				return flip(m)
			}
			return forward(m)
		}},
		"a tampered frame": {gets: 1, at: "get1", code: "FRAME_INVALID", close: 4008, edit: func(m vaulttest.Message, n int, _ []vaulttest.Message) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToPage && n == 1 {
				return flip(m)
			}
			return forward(m)
		}},
		"the page's own frame reflected back to it": {gets: 1, at: "get1", code: "FRAME_INVALID", close: 4008, edit: func(m vaulttest.Message, n int, _ []vaulttest.Message) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToEngine && n == 1 {
				return []vaulttest.Delivery{{SID: m.Session.SID, Dir: vaulttest.ToPage, Data: m.Data}}
			}
			return forward(m)
		}},
		"an earlier response replayed": {gets: 2, at: "get2", code: "FRAME_INVALID", close: 4008, edit: func(m vaulttest.Message, n int, kept []vaulttest.Message) []vaulttest.Delivery {
			if m.Dir == vaulttest.ToPage && n == 2 {
				for _, k := range kept {
					if k.Dir == vaulttest.ToPage {
						first := k
						if bytes.Equal(first.Data[:2], []byte{0x01, 0x03}) {
							return []vaulttest.Delivery{vaulttest.Forward(first), vaulttest.Forward(m)}
						}
					}
				}
			}
			return forward(m)
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := &hostileWire{seen: map[vaulttest.Direction]int{vaulttest.ToEngine: 0, vaulttest.ToPage: 0}, edit: c.edit}
			s := newHostileVaultSession(t, h)
			steps := runPortalPage(t, s, s.approvalPath(), c.gets)
			require.Contains(t, steps, "error")
			require.Equal(t, c.code, steps["error"].Code, steps["error"])
			require.NotContains(t, steps, c.at, "the page used nothing from a broken session")
			require.Eventually(t, func() bool { return h.closedWith(c.close) }, 5*time.Second, 5*time.Millisecond,
				"the page closes with %d", c.close)
			if c.at == "open" {
				require.Equal(t, "RelayError", steps["error"].Name)
				require.Contains(t, steps["error"].PersonMessage, "HANDSHAKE_FAILED")
				require.NotContains(t, steps, "get1")
			}
			if c.at == "get2" {
				require.Equal(t, http.StatusOK, steps["get1"].Status, "the first answer was the engine's own")
			}
		})
	}
}

// newHostileVaultSession is newVaultSession behind a Vault that alters
// the session as h says.
func newHostileVaultSession(t *testing.T, h *hostileWire) *vaultSession {
	t.Helper()
	return newVaultSessionWith(t, &wire{}, vaulttest.Options{Tamper: h.tamper, OnSessionClose: h.onClose})
}
