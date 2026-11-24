package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// A key is trusted on the record when its latest trust event is an ADDED,
// in the order the ledger gives.
func TestLedgerTrustedKeys(t *testing.T) {
	require.Nil(t, ledgerTrustedKeys(nil))
	require.Equal(t, []string{"a", "c"}, ledgerTrustedKeys([]guardmodel.PluginTrustEvent{
		{KeyID: "a", Kind: guardmodel.PluginTrustAdded},
		{KeyID: "b", Kind: guardmodel.PluginTrustRemoved},
		{KeyID: "c", Kind: guardmodel.PluginTrustAdded},
	}))
	require.Nil(t, ledgerTrustedKeys([]guardmodel.PluginTrustEvent{{KeyID: "b", Kind: guardmodel.PluginTrustRemoved}}))
	require.Nil(t, ledgerTrustedKeys([]guardmodel.PluginTrustEvent{{KeyID: "d", Kind: "PLUGIN_SOMETHING_ELSE"}}), "only an ADDED trusts a key")
}
