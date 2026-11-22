package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/keyfile"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// engineVault is the engine's keys and its socket to the Vault (CONTRACT.md,
// Vault channel).
type engineVault struct {
	// client keeps the socket; nil when the engine does not dial out.
	client *vault.Client
	// status is vault in status: KEY_ERROR, OFF, or the socket's state.
	status func() vault.Status
	// keys are the engine's keys, nil when the key file is refused
	// (KEY_ERROR): they sign receipts whatever vault says.
	keys *channel.EngineKeys
}

// receipts is the signer of the agents' receipts: none (a nil interface)
// when the key file is refused, and the answers then carry noReceipt.
func (v engineVault) receipts() agent.ReceiptSigner {
	if v.keys == nil {
		return nil
	}
	return v.keys
}

// openVault loads the engine's keys, making them on the first start whatever
// vault says (VC-36: receipts need the signing key on every path), and
// prepares the socket when vault is ON and the pages are the portal. A key
// file that is refused is left as it is: the engine serves MCP and the local
// pages as usual, never dials out, and status says KEY_ERROR. Sessions
// resolve their token in live and are answered by pages; with either nil,
// every session is refused at message 1.
func openVault(cfg config.Config, stateDir string, now func() time.Time, log *slog.Logger, live *relayLinks, pages vault.Dispatcher) engineVault {
	keys, err := loadEngineKeys(stateDir, now)
	if err != nil {
		log.Error("engine key file refused: the Vault stays off and links are long links until it is fixed; "+
			"correct the file's owner (the engine's OS user) and mode (0600), it is never replaced", "err", err)
		return engineVault{status: vault.KeyErrorStatus}
	}
	off := engineVault{status: func() vault.Status { return vault.OffStatus(keys) }, keys: keys}
	if !cfg.VaultEnabled() {
		return off
	}
	opts := vault.Options{URL: cfg.VaultURL, Keys: keys, Log: log.With("component", "vault"), Now: now, Pages: pages}
	if live != nil {
		opts.Links, opts.SessionLinks = live, live
	}
	client, err := vault.New(opts)
	if err != nil {
		log.Error("the Vault stays off", "err", err)
		return off
	}
	return engineVault{client: client, status: client.Status, keys: keys}
}

// pruneInterval is how often the engine drops expired links, so an expired
// relay link is unregistered at the Vault soon after its expiry.
const pruneInterval = time.Minute

// relayLinks are every agent's link store as the Vault client sees them: the
// live relay links it registers again after each READY, and the link a
// LINK_CONFLICT revokes (VC-42).
type relayLinks struct {
	log    *slog.Logger
	mu     sync.Mutex
	stores []*links.Secrets
	// agents names each store's agent, by index.
	agents []string
}

func newRelayLinks(log *slog.Logger) *relayLinks { return &relayLinks{log: log} }

// add takes an agent's store; its dropped relay links are unregistered
// with unregister.
func (r *relayLinks) add(agent string, s *links.Secrets, unregister func(channel.LinkToken)) {
	s.OnDrop(unregister)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stores = append(r.stores, s)
	r.agents = append(r.agents, agent)
}

func (r *relayLinks) all() []*links.Secrets {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.stores)
}

// Live lists every agent's live relay links.
func (r *relayLinks) Live() []vault.Link {
	var out []vault.Link
	for _, s := range r.all() {
		for _, l := range s.Relay() {
			out = append(out, vault.Link{Token: l.Token, Item: l.Item, ExpiresAt: l.ExpiresAt})
		}
	}
	return out
}

// Session is the live relay link of token, in whichever agent's store holds
// it. Every store is asked, so the time taken does not tell which agent, or
// whether any, holds the token.
func (r *relayLinks) Session(token channel.LinkToken) (vault.SessionLink, bool) {
	var out vault.SessionLink
	found := false
	r.mu.Lock()
	stores, agents := slices.Clone(r.stores), slices.Clone(r.agents)
	r.mu.Unlock()
	for i, s := range stores {
		l, ok := s.Session(token)
		if ok && !found {
			out = vault.SessionLink{Token: l.Keys.Token, Agent: agents[i], Item: l.Item, PSK: l.Keys.PSK, ExpiresAt: l.ExpiresAt}
			found = true
		}
		l.Keys.PSK.Zero()
	}
	return out, found
}

// Conflict revokes the link of token in whichever store holds it.
func (r *relayLinks) Conflict(token channel.LinkToken) {
	for _, s := range r.all() {
		held, err := s.RevokeToken(token)
		if err != nil {
			r.log.Error("revoke a link another engine registered", "err", err)
		}
		if held {
			return
		}
	}
}

// RevokeAll revokes every agent's relay links, unregistering their tokens.
func (r *relayLinks) RevokeAll() {
	for _, s := range r.all() {
		if err := s.RevokeRelay(); err != nil {
			r.log.Error("revoke the relay links", "err", err)
		}
	}
}

// pruneEvery drops expired links every interval until ctx ends.
func (r *relayLinks) pruneEvery(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, s := range r.all() {
				s.Prune()
			}
		}
	}
}

// loadEngineKeys reads <stateDir>/channel.json, creating the directory and
// the file when they do not exist.
func loadEngineKeys(stateDir string, now func() time.Time) (*channel.EngineKeys, error) {
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return nil, err
	}
	return keyfile.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), now)
}

// LoadOrCreateEngineKeys is keyfile.LoadOrCreateKeys, for the CLI, which
// does not import the stores.
func LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return keyfile.LoadOrCreateKeys(path, now)
}

// ReadEngineKeys is keyfile.LoadKeys, for the CLI: it reads and checks an
// existing key file and never writes.
func ReadEngineKeys(path string) (*channel.EngineKeys, error) {
	return keyfile.LoadKeys(path)
}

// VaultStatus is status.vault for every agent's status tool: OFF (with the
// engine id when the keys load), KEY_ERROR, or the socket's state.
func (v engineVault) VaultStatus() agent.VaultStatus {
	st := v.status()
	return agent.VaultStatus{State: string(st.State), EngineID: st.EngineID, Fingerprint: st.Fingerprint}
}
