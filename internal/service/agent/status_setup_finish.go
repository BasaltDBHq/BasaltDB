package agent

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Finishing a setup from the laptop (CONTRACT.md, Setup from your laptop, On
// the engine). On status, on every call while an INSTALL setup holds the
// tools, and at each heartbeat, the engine logs in with the agent's own
// credential (the .pending one first) and looks for the pending setupId in
// basalt_meta.agent_setups. Found: the setup is DONE (RI-10). The engine
// promotes the .pending credential when that is the one that found it,
// clears setup from engine.json, and serves the agent, with no restart. The
// guard version, the grants and the passkeys stay status's usual problems
// (GUARD_OUTDATED, PERMISSION_DENIED on use, NO_PASSKEY), not conditions for
// DONE. Nothing the agent or a client says is taken as proof: only the
// database, read as the agent.

// SetupFinisher finishes an agent's pending setup on the engine's machine.
type SetupFinisher interface {
	// PendingRecorded logs in with the agent's .pending credential, when
	// there is one for the same database and role as the engine's, and
	// reports whether setup id is recorded. has is false when there is no
	// such credential or the database refuses its login.
	PendingRecorded(ctx context.Context, id uuid.UUID) (recorded, has bool, err error)
	// Finish clears setup id from the agent's entry in engine.json under the
	// agent's lock, after moving the .pending credential PendingRecorded
	// logged in with over the credential file when promote is set. A config
	// whose pending setup is no longer id is left as it is.
	Finish(ctx context.Context, id string, promote bool) error
}

// noFinisher has no .pending credential and no config to clear.
type noFinisher struct{}

func (noFinisher) PendingRecorded(context.Context, uuid.UUID) (bool, bool, error) {
	return false, false, nil
}

func (noFinisher) Finish(context.Context, string, bool) error { return nil }

// LoginRefused reports whether err is the database refusing a login (the
// role does not exist, or has another password).
func LoginRefused(err error) bool {
	return err != nil && ErrorMap{}.ToolError(err).Reason == guidance.ReasonCredentialRejected
}

// notRecordedFor is how long a held call trusts an earlier call that found
// the pending setup not recorded, so a burst of calls while the person runs
// the code costs one login, not one each. status always reads afresh: it is
// what the agent calls once the person says the setup ran.
const notRecordedFor = 5 * time.Second

// setupCache remembers when a setup was last found not recorded.
type setupCache struct {
	mu sync.Mutex
	id string
	at time.Time
}

// fresh reports whether setup id was found not recorded within
// notRecordedFor of now.
func (c *setupCache) fresh(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id == id && !now.Before(c.at) && now.Sub(c.at) < notRecordedFor
}

// remember records that setup id was found not recorded at now.
func (c *setupCache) remember(id string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id, c.at = id, now
}

// pendingSetup is the agent's pending setup, nil when none is.
func (sc *statusKeeper) pendingSetup() *config.Setup {
	sc.setupMu.Lock()
	defer sc.setupMu.Unlock()
	return sc.setup
}

// setupFinished forgets the pending setup id once it is recorded.
func (sc *statusKeeper) setupFinished(id string) {
	sc.setupMu.Lock()
	defer sc.setupMu.Unlock()
	if sc.setup != nil && sc.setup.SetupID == id {
		sc.setup = nil
	}
}

// AdmitTick is the heartbeat's gate: it first looks for a pending setup of
// any kind in the database, so a rotated credential is picked up and
// engine.json cleared even when nobody calls status, then admits as Admit.
func (sc *statusKeeper) AdmitTick(ctx context.Context) error {
	if d := sc.statusDeps(); d.setup != nil && d.setup.Kind != guardmodel.SetupInstall {
		d.pendingRecorded(ctx)
	}
	return sc.Admit(ctx)
}

// recordedAsAgent reads, with the agent's own credential, whether setup id
// is recorded: with the .pending credential first, then the engine's own.
// Recorded, it finishes the setup.
func (s statusDeps) recordedAsAgent(ctx context.Context, id uuid.UUID) (bool, error) {
	recorded, has, err := s.finisher.PendingRecorded(ctx, id)
	if err != nil {
		s.log.Error("read the pending setup with the pending credential", "err", err)
	}
	promote := err == nil && has && recorded
	if !promote {
		recorded, err = s.probe.SetupRecorded(ctx, id)
		if err != nil || !recorded {
			return recorded, err
		}
	}
	s.finish(ctx, promote)
	return true, nil
}

// finish clears the recorded setup from the config and forgets it. The setup
// stays pending in memory, so the next call or heartbeat tries again, when
// the credential could not be promoted (the engine still logs in with the
// old one), the agent's lock was held (basalt init --remote is running), or
// a lock file cannot be opened at all: status then reports
// LOCK_FILE_UNUSABLE until a try opens it (CONTRACT.md, Lock files). Any
// other failure, such as a config the engine cannot write, is logged and
// the setup forgotten: the database, not the file, decides that it is done.
func (s statusDeps) finish(ctx context.Context, promote bool) {
	id := s.setup.SetupID
	err := s.finisher.Finish(ctx, id, promote)
	var unusable *config.LockUnusableError
	switch {
	case errors.As(err, &unusable):
		s.lockTrouble.set(unusable.Path)
	case err == nil || !errors.Is(err, config.ErrLocked):
		s.lockTrouble.set("")
	}
	if err != nil {
		s.log.Error("finish the agent's setup", "setupId", id, "promote", promote, "err", err)
		if promote || errors.Is(err, config.ErrLocked) || unusable != nil {
			return
		}
	}
	s.finished(id)
}

// lockTrouble is the lock file the last try to finish a setup could not
// open, "" when none.
type lockTrouble struct {
	mu   sync.Mutex
	path string
}

func (l *lockTrouble) set(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.path = path
}

func (l *lockTrouble) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.path
}

// lockFileSteps: the person gives the lock file back to the engine's user
// with root, on the engine's machine. A PERSON step on an agent-operated
// engine too: it needs root.
func lockFileSteps(b *guidance.Steps, path string) string {
	cmd := "sudo chown " + engineUserName() + " " + guidance.ShellQuote(path)
	b.RunCommand(cmd, "Run this on the engine's machine: the engine cannot open this lock file.")
	b.TellAgent("Tell the agent when it is done.")
	return "The engine cannot open its lock file " + path + " (a root process left it behind), so it cannot finish the agent's setup. On the engine's machine, run: " + cmd + " then tell the agent."
}

// engineUserName is the engine's OS user, by name when it has one, else
// its uid (chown takes both).
func engineUserName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Geteuid())
}
