package engine

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// engineVault is the engine's keys and its socket to the Vault (CONTRACT.md,
// Vault channel).
type engineVault struct {
	// client keeps the socket; nil when the engine does not dial out.
	client *vault.Client
	// status is vault in status: KEY_ERROR, OFF, or the socket's state.
	status func() vault.Status
}

// openVault loads the engine's keys, making them on the first start whatever
// vault says (VC-36: receipts need the signing key on every path), and
// prepares the socket when vault is ON and the pages are the portal. A key
// file that is refused is left as it is: the engine serves MCP and the local
// pages as usual, never dials out, and status says KEY_ERROR.
func openVault(cfg config.Config, stateDir string, now func() time.Time, log *slog.Logger) engineVault {
	keys, err := loadEngineKeys(stateDir, now)
	if err != nil {
		log.Error("engine key file refused: the Vault stays off and links are long links until it is fixed; "+
			"correct the file's owner (the engine's OS user) and mode (0600), it is never replaced", "err", err)
		return engineVault{status: vault.KeyErrorStatus}
	}
	off := engineVault{status: func() vault.Status { return vault.OffStatus(keys) }}
	if !cfg.VaultEnabled() {
		return off
	}
	client, err := vault.New(vault.Options{URL: cfg.VaultURL, Keys: keys, Log: log.With("component", "vault"), Now: now})
	if err != nil {
		log.Error("the Vault stays off", "err", err)
		return off
	}
	return engineVault{client: client, status: client.Status}
}

// loadEngineKeys reads <stateDir>/channel.json, creating the directory and
// the file when they do not exist.
func loadEngineKeys(stateDir string, now func() time.Time) (*channel.EngineKeys, error) {
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return nil, err
	}
	return channel.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), now)
}
