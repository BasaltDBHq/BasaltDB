package vault_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// pageStep is one line the portal page's script prints.
type pageStep struct {
	Step          string          `json:"step"`
	Status        int             `json:"status"`
	Body          json.RawMessage `json:"body"`
	Socket        string          `json:"socket"`
	Engine        map[string]any  `json:"engine"`
	Length        int             `json:"length"`
	Sent          int             `json:"sent"`
	Type          string          `json:"type"`
	Code          string          `json:"code"`
	PersonMessage string          `json:"personMessage"`
}

// runPage runs the portal's DIRECT transport (web/lib/direct.js and
// channel.js, under node) against e for link l, with the page pinning
// pinnedID, and returns its steps by name.
func runPage(t *testing.T, e *directEngine, keys *channel.EngineKeys, l link, pinnedID string) map[string]pageStep {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; make web-check needs it too")
	}
	arg, err := json.Marshal(map[string]string{
		"secret":    l.secret,
		"engineKey": base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI()),
		"engineId":  keys.EngineID(),
		"item":      l.item.String(),
		"pinnedId":  pinnedID,
	})
	require.NoError(t, err)
	cmd := exec.CommandContext(ctxWait(t), node, "testdata/direct_page.mjs", e.url, string(arg))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	steps := map[string]pageStep{}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	for sc.Scan() {
		var s pageStep
		require.NoError(t, json.Unmarshal(sc.Bytes(), &s), sc.Text())
		steps[s.Step] = s
	}
	return steps
}

// The portal page opens a DIRECT session to the engine's listener with the
// pinned key, sends requests whose bodies take several frames, and reads
// answers that take several frames: byte for byte the session the Go page
// runs.
func TestPortalPageRunsADirectSession(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	e := newDirectEngine(t, func(o *vault.DirectOptions) { o.Keys = keys }, nil)
	l := newLink(t)
	e.hold(l)
	steps := runPage(t, e, keys, l, keys.EngineID())
	require.NotContains(t, steps, "error", steps["error"])

	require.Equal(t, "wss://engine.example.com/v1/session", steps["open"].Socket)
	require.Equal(t, keys.EngineID(), steps["open"].Engine["engineId"])

	var got echo
	require.Equal(t, 200, steps["get"].Status)
	require.NoError(t, json.Unmarshal(steps["get"].Body, &got))
	require.Equal(t, "GET", got.Method)
	require.Equal(t, l.item.String(), got.Item)
	require.Equal(t, map[string]string{"basalt-link-secret": l.secret, "origin": "https://portal.basaltvault.app"}, got.Headers)
	require.Zero(t, got.BodyLen)

	require.Equal(t, 200, steps["post"].Status)
	require.NoError(t, json.Unmarshal(steps["post"].Body, &got))
	require.Equal(t, "POST", got.Method)
	require.Equal(t, "application/json", got.Headers["content-type"])
	sent := strings.Repeat("é\"\n€", 1500)
	body, err := json.Marshal(map[string]string{"pad": sent})
	require.NoError(t, err)
	require.Equal(t, len(body), got.BodyLen, "the engine got the whole body, across frames")

	require.Equal(t, 200, steps["big"].Status)
	require.Equal(t, utf8.RuneCountInString(bigBody), steps["big"].Length)
	require.Equal(t, "text/plain", steps["big"].Type)
}

// A page that pinned another engine closes the session before it shows
// anything, and says the address answers with a different engine.
func TestPortalPageRefusesAnotherEngine(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	e := newDirectEngine(t, func(o *vault.DirectOptions) { o.Keys = keys }, nil)
	l := newLink(t)
	e.hold(l)
	steps := runPage(t, e, keys, l, newKeys(t).EngineID())
	require.Contains(t, steps, "error")
	require.Equal(t, "UNAVAILABLE", steps["error"].Code)
	require.Contains(t, steps["error"].PersonMessage, "different engine than the one this device pinned")
	e.pages.mu.Lock()
	defer e.pages.mu.Unlock()
	require.Empty(t, e.pages.got, "no request reached the engine")
}

// A link the engine does not hold is refused at message 1, and the page
// reads it as a link that is gone.
func TestPortalPageReadsARefusedLink(t *testing.T) {
	t.Parallel()
	keys := newKeys(t)
	e := newDirectEngine(t, func(o *vault.DirectOptions) { o.Keys = keys }, nil)
	steps := runPage(t, e, keys, newLink(t), keys.EngineID())
	require.Equal(t, "NOT_FOUND", steps["error"].Code)
}
