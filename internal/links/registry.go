// Package links is the links service: the engine's relay links across every
// agent's link store.
package links

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	corelinks "github.com/basaltdbhq/basaltdb/internal/core/links"
)

// Registry holds every agent's link store as the Vault client sees them:
// the live relay links it registers again after each READY, and the link a
// LINK_CONFLICT revokes (VC-42).
type Registry struct {
	log    *slog.Logger
	mu     sync.Mutex
	stores []*corelinks.Secrets
	// agents names each store's agent, by index.
	agents []string
}

// NewRegistry returns a registry with no stores.
func NewRegistry(log *slog.Logger) *Registry { return &Registry{log: log} }

// Add takes an agent's store; its dropped relay links are unregistered
// with unregister.
func (r *Registry) Add(agent string, s *corelinks.Secrets, unregister func(channel.LinkToken)) {
	s.OnDrop(unregister)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stores = append(r.stores, s)
	r.agents = append(r.agents, agent)
}

func (r *Registry) all() []*corelinks.Secrets {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.stores)
}

// Live lists every agent's live relay links.
func (r *Registry) Live() []corelinks.RelayLink {
	var out []corelinks.RelayLink
	for _, s := range r.all() {
		out = append(out, s.Relay()...)
	}
	return out
}

// Session is the live relay link of token and the agent whose store holds
// it. Every store is asked, so the time taken does not tell which agent, or
// whether any, holds the token. The caller zeroes the returned PSK once it
// is used.
func (r *Registry) Session(token channel.LinkToken) (string, corelinks.SessionLink, bool) {
	var (
		agent string
		out   corelinks.SessionLink
	)
	found := false
	r.mu.Lock()
	stores, agents := slices.Clone(r.stores), slices.Clone(r.agents)
	r.mu.Unlock()
	for i, s := range stores {
		l, ok := s.Session(token)
		if ok && !found {
			agent, out = agents[i], l
			found = true
		}
		l.Keys.PSK.Zero()
	}
	return agent, out, found
}

// Conflict revokes the link of token in whichever store holds it.
func (r *Registry) Conflict(token channel.LinkToken) {
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
func (r *Registry) RevokeAll() {
	for _, s := range r.all() {
		if err := s.RevokeRelay(); err != nil {
			r.log.Error("revoke the relay links", "err", err)
		}
	}
}

// PruneEvery drops expired links every interval until ctx ends.
func (r *Registry) PruneEvery(ctx context.Context, interval time.Duration) {
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
