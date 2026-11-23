package handoff

import (
	"context"
	"errors"
	"log/slog"
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

// NoFinisher has no .pending credential and no config to clear.
type NoFinisher struct{}

func (NoFinisher) PendingRecorded(context.Context, uuid.UUID) (bool, bool, error) {
	return false, false, nil
}

func (NoFinisher) Finish(context.Context, string, bool) error { return nil }

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

// SetupKeeper owns the agent's pending setup: StatusDeps.Setup until the
// database shows it recorded, the held calls' cache of a setup not recorded
// yet, and the lock file the engine could not open while finishing one
// (problem LOCK_FILE_UNUSABLE).
type SetupKeeper struct {
	mu          sync.Mutex
	setup       *config.Setup
	notRecorded setupCache
	lockTrouble lockTrouble
}

// NewSetupKeeper is the keeper of the agent's pending setup setup, nil when
// it has none.
func NewSetupKeeper(setup *config.Setup) *SetupKeeper { return &SetupKeeper{setup: setup} }

// Watch is the pending setup as a call reads it now: with the database the
// credential names, what it reads of the database, what finishes the setup,
// and the host's logger and clock.
func (k *SetupKeeper) Watch(database string, probe setupProbe, finisher SetupFinisher, log *slog.Logger, now func() time.Time) SetupWatch {
	return SetupWatch{
		setup: k.pending(), database: database, probe: probe, finisher: finisher,
		finished: k.finished, notRecorded: &k.notRecorded, lockTrouble: &k.lockTrouble,
		log: log, now: now,
	}
}

// NewLocalWatch is the pending setup as basalt status reads it for an engine
// run as the person: the running engine finishes the setup, so nothing here
// does.
func NewLocalWatch(setup *config.Setup, probe setupProbe, log *slog.Logger, now func() time.Time) SetupWatch {
	return SetupWatch{
		setup: setup, probe: probe, finisher: NoFinisher{}, finished: func(string) {},
		notRecorded: &setupCache{}, lockTrouble: &lockTrouble{}, log: log, now: now,
	}
}

// pending is the agent's pending setup, nil when none is.
func (k *SetupKeeper) pending() *config.Setup {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.setup
}

// finished forgets the pending setup id once it is recorded.
func (k *SetupKeeper) finished(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.setup != nil && k.setup.SetupID == id {
		k.setup = nil
	}
}

// setupProbe is what the setup watch reads of the database: whether a setup
// is recorded, and the latest one.
type setupProbe interface {
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	LatestSetup(ctx context.Context) (guardmodel.AgentSetup, bool, error)
}

// SetupWatch is the agent's pending setup as one call reads it: the setup as
// it stands, what finishes it, and what it reads of the database.
type SetupWatch struct {
	setup *config.Setup
	// database names the credential's database (Deps.Database).
	database string
	probe    setupProbe
	finisher SetupFinisher
	// finished forgets the pending setup once the database shows it
	// recorded.
	finished func(id string)
	// notRecorded remembers, for a few seconds, that a held call found the
	// pending setup not recorded (gate).
	notRecorded *setupCache
	// lockTrouble is the lock file finishing a setup could not open.
	lockTrouble *lockTrouble
	log         *slog.Logger
	now         func() time.Time
}

// Pending is the pending setup, nil when none is.
func (s SetupWatch) Pending() *config.Setup { return s.setup }

// LockTroubleFile is the lock file the last try to finish a setup could not
// open, "" when none.
func (s SetupWatch) LockTroubleFile() string { return s.lockTrouble.get() }

// recordedAsAgent reads, with the agent's own credential, whether setup id
// is recorded: with the .pending credential first, then the engine's own.
// Recorded, it finishes the setup.
func (s SetupWatch) recordedAsAgent(ctx context.Context, id uuid.UUID) (bool, error) {
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
func (s SetupWatch) finish(ctx context.Context, promote bool) {
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

// LockFileSteps: the person gives the lock file back to the engine's user
// with root, on the engine's machine. A PERSON step on an agent-operated
// engine too: it needs root.
func LockFileSteps(b *guidance.Steps, path string) string {
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
