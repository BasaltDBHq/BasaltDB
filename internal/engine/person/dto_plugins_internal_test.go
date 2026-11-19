package person

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// The person socket carries the plugins the ledger records as served, so
// basalt log shows the same Plugins line in service mode.
func TestHealthCarriesThePlugins(t *testing.T) {
	t.Parallel()
	ps := []ledger.PluginHealth{
		{Name: "acme-ner", Instance: "default", Version: "1.4.0", SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Endpoint: "LOCAL", Files: "NONE", Network: "NOT_ENFORCED"},
		{Name: "acme-ner", Instance: "eu", Version: "1.5.0", SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Endpoint: "REMOTE", Host: "ner.acme.example:443"},
	}
	for _, in := range [][]ledger.PluginHealth{ps, {}, nil} {
		raw, err := json.Marshal(healthFromDomain(ledger.Health{Plugins: in}))
		require.NoError(t, err)
		var back healthDTO
		require.NoError(t, json.Unmarshal(raw, &back))
		require.Equal(t, in, back.toDomain().Plugins)
	}
}

func TestHealthCarriesThePluginsCutAndProblem(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(healthFromDomain(ledger.Health{PluginsMore: 4, PluginsProblem: "boom"}))
	require.NoError(t, err)
	var back healthDTO
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Equal(t, 4, back.toDomain().PluginsMore)
	require.Equal(t, "boom", back.toDomain().PluginsProblem)
}
