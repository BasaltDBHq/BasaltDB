package vault

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// TestChannelSpecMatchesVaultLimits checks the limits the outside-reviewer
// spec quotes (docs/security/vault-channel-spec.md, the "vault" constants
// block) against the engine's socket and session code, in both directions.
func TestChannelSpecMatchesVaultLimits(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../../docs/security/vault-channel-spec.md")
	require.NoError(t, err)
	_, rest, ok := strings.Cut(string(raw), "```constants vault\n")
	require.True(t, ok, "the spec has no vault constants block")
	body, _, ok := strings.Cut(rest, "```")
	require.True(t, ok)
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(body), "\n") {
		k, v, ok := strings.Cut(l, " = ")
		require.True(t, ok, l)
		got[k] = v
	}
	want := map[string]string{
		"message-1":            fmt.Sprintf("exactly %d bytes", channel.Message1Len),
		"message-2":            fmt.Sprintf("at most %d bytes", channel.Message2Max),
		"frame":                fmt.Sprintf("at most %d bytes", channel.FrameMax),
		"route-message":        fmt.Sprintf("at most %d bytes", maxRoute),
		"control-message":      fmt.Sprintf("at most %d bytes", maxControl),
		"request-body":         fmt.Sprintf("at most %d bytes", MaxRequestBody),
		"response-body":        "at most 16 MiB, checked by the page only",
		"handshake-time":       fmt.Sprintf("%d seconds", int(HandshakeTimeout.Seconds())),
		"idle-session":         fmt.Sprintf("%d minutes", int(IdleTimeout.Minutes())),
		"session-lifetime":     fmt.Sprintf("%d minutes", int(SessionLifetime.Minutes())),
		"requests-per-session": fmt.Sprint(MaxRequests),
		"sessions-per-link":    fmt.Sprint(MaxSessionsPerLink),
		"sessions-per-engine":  fmt.Sprint(MaxSessions),
		"handshakes-per-link":  fmt.Sprintf("%d per %d minutes", HandshakesPerLink, int(HandshakeWindow.Minutes())),
		"route-type":           fmt.Sprintf("0x%02x", typeRoute),
		"session-id-bytes":     fmt.Sprint(sidLen),
	}
	require.Equal(t, want, got)

	// The response limit is the page's (the engine never reads a response).
	page, err := os.ReadFile("../../../web/lib/channel.js")
	require.NoError(t, err)
	require.Contains(t, string(page), "const RESPONSE_MAX = 16 << 20;")
	require.Equal(t, 5*60, int(IdleTimeout.Seconds()))
}
