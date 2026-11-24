package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/platform/keyfile"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
)

// openVault loads the engine's keys, making them on the first start whatever
// vault says (VC-36: receipts need the signing key on every path), and
// prepares the socket when vault is ON and the pages are the portal. A key
// file that is refused is left as it is: the engine serves MCP and the local
// pages as usual, never dials out, and status says KEY_ERROR. Sessions
// resolve their token in live and are answered by pages; with either nil,
// every session is refused at message 1.
func openVault(cfg config.Config, stateDir string, now func() time.Time, log *slog.Logger, live *linksvc.Registry, pages vault.Dispatcher) vault.Engine {
	keys, err := loadEngineKeys(stateDir, now)
	if err != nil {
		log.Error("engine key file refused: the Vault stays off and links are long links until it is fixed; "+
			"correct the file's owner (the engine's OS user) and mode (0600), it is never replaced", "err", err)
		return vault.Engine{Status: vault.KeyErrorStatus}
	}
	off := vault.Engine{Status: func() vault.Status { return vault.OffStatus(keys) }, Keys: keys}
	if !cfg.VaultEnabled() {
		return off
	}
	opts := vault.Options{URL: cfg.VaultURL, Keys: keys, Log: log.With("component", "vault"), Now: now, Pages: pages}
	if live != nil {
		opts.Links, opts.SessionLinks = vaultLinks{live}, vaultLinks{live}
	}
	client, err := vault.New(opts)
	if err != nil {
		log.Error("the Vault stays off", "err", err)
		return off
	}
	return vault.Engine{Client: client, Status: client.Status, Keys: keys}
}

// pruneInterval is how often the engine drops expired links, so an expired
// relay link is unregistered at the Vault soon after its expiry.
const pruneInterval = time.Minute

// vaultLinks is the links registry as the Vault client reads it.
type vaultLinks struct{ *linksvc.Registry }

// Live lists every agent's live relay links.
func (v vaultLinks) Live() []vault.Link {
	live := v.Registry.Live()
	out := make([]vault.Link, 0, len(live))
	for _, l := range live {
		out = append(out, vault.Link{Token: l.Token, Item: l.Item, ExpiresAt: l.ExpiresAt})
	}
	return out
}

// Session is the live relay link of token, in whichever agent's store
// holds it.
func (v vaultLinks) Session(token channel.LinkToken) (vault.SessionLink, bool) {
	agent, l, ok := v.Registry.Session(token)
	defer l.Keys.PSK.Zero()
	if !ok {
		return vault.SessionLink{}, false
	}
	return vault.SessionLink{Token: l.Keys.Token, Agent: agent, Item: l.Item, PSK: l.Keys.PSK, ExpiresAt: l.ExpiresAt}, true
}

// loadEngineKeys reads <stateDir>/channel.json, creating the directory and
// the file when they do not exist.
func loadEngineKeys(stateDir string, now func() time.Time) (*channel.EngineKeys, error) {
	if err := os.MkdirAll(stateDir, engine.StateDirMode); err != nil {
		return nil, err
	}
	return keyfile.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), now)
}

// loadOrCreateEngineKeys is keyfile.LoadOrCreateKeys, for the CLI, which
// does not import the stores.
func loadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return keyfile.LoadOrCreateKeys(path, now)
}
