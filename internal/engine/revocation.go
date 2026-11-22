package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// recordReadTimeout bounds one read of this engine's record in an agent's
// database.
const recordReadTimeout = 5 * time.Second

// revocation is what each agent's database says of this engine's key, as
// the relay acts on it (CONTRACT.md, Vault channel, Engine revocation).
// The engine reads its record at start, at every heartbeat and at each
// relay session. Once an agent's database revoked the key, the engine
// hands that agent no relay short link, revokes its live ones (their
// tokens are unregistered at the Vault and their sessions closed with
// ENGINE_REVOKED) and refuses its sessions; when every agent's database
// revoked it, the engine leaves the Vault. A failed read keeps the last
// state, and a revoked key stays revoked: it is never recorded again.
type revocation struct {
	log      *slog.Logger
	engineID string
	mu       sync.Mutex
	agents   map[string]*agentRecord
	// leave ends the engine's socket to the Vault; nil when it has none.
	leave func()
	left  bool
}

// agentRecord is one agent's read of the record, its links, and what the
// last read said.
type agentRecord struct {
	read    agent.EngineRecordReader
	secrets *links.Secrets
	revoked bool
}

func newRevocation(engineID string, log *slog.Logger) *revocation {
	return &revocation{log: log, engineID: engineID, agents: map[string]*agentRecord{}}
}

// add watches name's record, read with read; its relay links are secrets.
func (r *revocation) add(name string, read agent.EngineRecordReader, secrets *links.Secrets) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[name] = &agentRecord{read: read, secrets: secrets}
}

// onLeave sets what ends the engine's socket once every agent's database
// revoked the key.
func (r *revocation) onLeave(leave func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leave = leave
}

// isRevoked reports what name's last read said.
func (r *revocation) isRevoked(name string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.agents[name]
	return a != nil && a.revoked
}

// check reads name's record and reports whether its database revoked this
// engine's key. The first read that finds it revoked revokes the agent's
// relay links, and, when every agent is revoked, has the engine leave the
// Vault.
func (r *revocation) check(ctx context.Context, name string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	a := r.agents[name]
	if a == nil || a.read == nil {
		r.mu.Unlock()
		return false
	}
	if a.revoked {
		r.mu.Unlock()
		return true
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, recordReadTimeout)
	defer cancel()
	rec, err := a.read(ctx, r.engineID)
	if err != nil {
		r.log.Debug("read the engine's record; keeping the last state", "agent", name, "err", err)
		return false
	}
	if rec == nil || rec.RevokedAt == nil {
		return false
	}

	r.mu.Lock()
	if a.revoked {
		r.mu.Unlock()
		return true
	}
	a.revoked = true
	every := true
	for _, other := range r.agents {
		every = every && other.revoked
	}
	leave := r.leave
	if every && !r.left {
		r.left = true
	} else {
		leave = nil
	}
	r.mu.Unlock()

	r.log.Warn("the agent's database revoked this engine's key: its relay links are revoked and its sessions refused", "agent", name)
	if err := a.secrets.RevokeRelay(); err != nil {
		r.log.Error("revoke the relay links of a revoked engine", "agent", name, "err", err)
	}
	if leave != nil {
		r.log.Warn("every agent's database revoked this engine's key: leaving the Vault")
		leave()
	}
	return true
}

// endRevoked unregisters a revoked agent's token at the Vault and closes its
// open sessions with ENGINE_REVOKED. Like Unregister it waits for nothing.
func endRevoked(c *vault.Client) func(channel.LinkToken) {
	return func(token channel.LinkToken) { c.UnregisterWith(token, channel.ErrEngineRevoked) }
}

// gate is the heartbeat's gate with the record read first.
func (r *revocation) gate(name string, next func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		r.check(ctx, name)
		return next(ctx)
	}
}

// errEngineRevoked refuses a relay registration for an agent whose
// database revoked this engine's key.
var errEngineRevoked = errors.New("the agent's database revoked this engine's key: no relay short link")

// revocableRelay is an agent's link relay that, once the agent's database
// revoked this engine's key, registers nothing: the agent then hands over
// long links.
type revocableRelay struct {
	next    agent.LinkRelay
	revoked func() bool
}

func (r revocableRelay) Connected() bool { return !r.revoked() && r.next.Connected() }

func (r revocableRelay) Register(ctx context.Context, token channel.LinkToken, expires time.Time) error {
	if r.revoked() {
		return errEngineRevoked
	}
	return r.next.Register(ctx, token, expires)
}
