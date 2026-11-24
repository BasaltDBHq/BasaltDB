package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
)

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestOpenVaultMakesKeysOnFirstStartWhateverVaultSays(t *testing.T) {
	t.Parallel()
	stateDir := filepath.Join(t.TempDir(), "state") // not there yet
	ev := openVault(config.Config{}, stateDir, time.Now, quietLog(), nil, nil)
	require.Nil(t, ev.Client, "vault unset: no socket")

	st := ev.Status()
	require.Equal(t, vault.StateOff, st.State)
	require.Len(t, st.EngineID, 22)
	require.NotEmpty(t, st.Fingerprint)

	fi, err := os.Stat(filepath.Join(stateDir, channel.KeyFileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	// The next start loads the same keys.
	again := openVault(config.Config{}, stateDir, time.Now, quietLog(), nil, nil)
	require.Equal(t, st.EngineID, again.Status().EngineID)
}

func TestOpenVaultReportsKeyErrorAndLeavesTheFile(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, channel.KeyFileName)
	openVault(config.Config{}, stateDir, time.Now, quietLog(), nil, nil)
	require.NoError(t, os.Chmod(path, 0o644))
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal}
	ev := openVault(cfg, stateDir, time.Now, quietLog(), nil, nil)
	require.Nil(t, ev.Client, "KEY_ERROR never dials out")
	require.Equal(t, vault.Status{State: vault.StateKeyError}, ev.Status())

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "a refused key file is never replaced")
}

func TestOpenVaultStaysOffWithLocalPages(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Vault: config.VaultOn, PagesURL: "http://localhost:7777"}
	ev := openVault(cfg, t.TempDir(), time.Now, quietLog(), nil, nil)
	require.Nil(t, ev.Client)
	require.Equal(t, vault.StateOff, ev.Status().State)
}

func TestOpenVaultDialsTheVault(t *testing.T) {
	t.Parallel()
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, t.TempDir(), time.Now, quietLog(), nil, nil)
	require.NotNil(t, ev.Client)
	require.Equal(t, vault.StateConnecting, ev.Status().State)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ev.Client.Run(ctx) }()
	require.Eventually(t, func() bool { return ev.Status().State == vault.StateConnected }, 5*time.Second, 5*time.Millisecond)
	require.True(t, v.Connected(ev.Status().EngineID))
	cancel()
	require.NoError(t, <-done)
}
