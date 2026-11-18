package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

const vaultAgents = `"socketDir": "/s", "agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}]`

func TestLoadVault(t *testing.T) {
	t.Parallel()
	c, err := config.Load(write(t, "engine.json",
		`{`+vaultAgents+`, "vault": "ON", "vaultUrl": "ws://127.0.0.1:8787", "pagesUrl": "https://portal.basaltvault.app"}`, 0o600))
	require.NoError(t, err)
	require.Equal(t, config.VaultOn, c.Vault)
	require.Equal(t, "ws://127.0.0.1:8787", c.VaultURL)
	require.True(t, c.VaultEnabled())
}

func TestVaultEnabled(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		cfg  config.Config
		want bool
	}{
		"on with the portal":    {config.Config{Vault: config.VaultOn, PagesURL: "https://portal.basaltvault.app"}, true},
		"off with the portal":   {config.Config{Vault: config.VaultOff, PagesURL: "https://portal.basaltvault.app"}, false},
		"unset with the portal": {config.Config{PagesURL: "https://portal.basaltvault.app"}, false},
		"on with local pages":   {config.Config{Vault: config.VaultOn, PagesURL: "http://localhost:7777"}, false},
		"on with the default":   {config.Config{Vault: config.VaultOn}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.cfg.VaultEnabled())
		})
	}
}

func TestCheckVaultURL(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"", "ws://127.0.0.1:8787", "ws://[::1]:8787", "ws://localhost:8787", "ws://LOCALHOST:1/", "ws://127.0.0.1"} {
		require.NoError(t, config.CheckVaultURL(ok), ok)
	}
	for _, bad := range []string{
		"wss://relay.basaltvault.app",
		"ws://relay.basaltvault.app",
		"ws://127.0.0.2:8787",
		"ws://10.0.0.1:8787",
		"ws://0.0.0.0:8787",
		"ws://localhost.evil.io:8787",
		"http://127.0.0.1:8787",
		"wss://127.0.0.1:8787",
		"ws://user@127.0.0.1:8787",
		"ws://127.0.0.1:8787/v1/engines/x",
		"ws://127.0.0.1:8787?x=1",
		"ws://127.0.0.1:8787#x",
		"127.0.0.1:8787",
	} {
		require.Error(t, config.CheckVaultURL(bad), bad)
	}
}

func TestLoadRefusesVault(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"vault lowercase":   `{` + vaultAgents + `, "vault": "on"}`,
		"vault other":       `{` + vaultAgents + `, "vault": "MAYBE"}`,
		"vaultUrl remote":   `{` + vaultAgents + `, "vaultUrl": "wss://relay.example.com"}`,
		"vaultUrl not ws":   `{` + vaultAgents + `, "vaultUrl": "http://127.0.0.1:1"}`,
		"vaultUrl with key": `{` + vaultAgents + `, "vaultUrl": "ws://127.0.0.1:1/?k=v"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(write(t, "engine.json", content, 0o600))
			require.Error(t, err)
		})
	}
}
