package setup_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

func TestVaultModeFlag(t *testing.T) {
	t.Parallel()
	var m setup.VaultMode
	require.NoError(t, m.Set("on"))
	require.Equal(t, config.VaultOn, m.Enum())
	require.NoError(t, m.Set("off"))
	require.Equal(t, config.VaultOff, m.Enum())
	for _, bad := range []string{"ON", "true", "", "yes"} {
		require.Error(t, m.Set(bad), bad)
	}
	require.Empty(t, setup.VaultMode("").Enum(), "no choice keeps the config's")
}
