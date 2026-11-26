package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
)

// TestLimitsMatchSharedFile checks the engine's channel limits, and the fake
// Vault's, against api/mcp/vault/limits.json, the file the Vault checks its
// own against. A limit in the file that no constant here pins, or a constant
// that differs from the file, fails.
func TestLimitsMatchSharedFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "mcp", "vault", "limits.json"))
	require.NoError(t, err)
	var file struct {
		Limits []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
			Unit  string `json:"unit"`
		} `json:"limits"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))

	secs := func(d time.Duration) int64 {
		require.Zero(t, d%time.Second, "%s is not whole seconds", d)
		return int64(d / time.Second)
	}
	// Each limit's constants: the engine's first, then the fake Vault's.
	engine := map[string][]int64{
		"MAX_FRAME":               {channel.FrameMax, vaulttest.MaxFrame},
		"MAX_ROUTE":               {maxRoute, vaulttest.MaxRoute},
		"MAX_CONTROL":             {maxControl, vaulttest.MaxControl},
		"MAX_EXPIRY_AHEAD":        {secs(vaulttest.MaxExpiryAhead)},
		"CHALLENGE_TTL":           {secs(AuthTimeout), secs(vaulttest.ChallengeTTL)},
		"MIN_LINKS_PER_ENGINE":    {vaulttest.MinLinksPerEngine},
		"MAX_SESSIONS_PER_LINK":   {MaxSessionsPerLink},
		"MAX_SESSIONS_PER_ENGINE": {MaxSessions},
		"MAX_HANDSHAKES_PER_LINK": {HandshakesPerLink},
		"HANDSHAKE_WINDOW":        {secs(HandshakeWindow)},
	}
	units := map[string]string{
		"MAX_FRAME": "BYTES", "MAX_ROUTE": "BYTES", "MAX_CONTROL": "BYTES",
		"MAX_EXPIRY_AHEAD": "SECONDS", "CHALLENGE_TTL": "SECONDS", "HANDSHAKE_WINDOW": "SECONDS",
		"MIN_LINKS_PER_ENGINE": "COUNT", "MAX_SESSIONS_PER_LINK": "COUNT",
		"MAX_SESSIONS_PER_ENGINE": "COUNT", "MAX_HANDSHAKES_PER_LINK": "COUNT",
	}

	inFile := make(map[string]bool, len(file.Limits))
	for _, l := range file.Limits {
		inFile[l.Name] = true
		consts, ok := engine[l.Name]
		require.True(t, ok, "limits.json has %s, which no engine constant pins", l.Name)
		require.Equal(t, units[l.Name], l.Unit, l.Name)
		for _, c := range consts {
			require.Equal(t, l.Value, c, "%s: limits.json and the Go constant differ", l.Name)
		}
	}
	for name := range engine {
		require.True(t, inFile[name], "limits.json lacks %s", name)
	}
}
