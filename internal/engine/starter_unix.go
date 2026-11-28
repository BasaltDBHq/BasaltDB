//go:build unix

package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

const (
	startLockName = "start.lock"
	engineLogName = "engine.log"
	startPoll     = 50 * time.Millisecond
)

// StarterOS is the starter's reach into the machine's files: its folders,
// the start, engine and supervisor locks, the binary and the engine log.
// engine/out/engineos is the real one.
type StarterOS interface {
	// MakeDirs makes dir and any missing parents with mode.
	MakeDirs(dir string, mode os.FileMode) error
	// LockFile takes the exclusive lock on path without waiting:
	// config.ErrLocked when another process holds it.
	LockFile(path string) (release func(), err error)
	// LockHolderRuns is true when a live process holds the pid lock at path.
	LockHolderRuns(path string) bool
	// StatPath is nil when path names a file, following links.
	StatPath(path string) error
	// ReadLastStop reads the supervisor's record at path; false when there
	// is no usable record.
	ReadLastStop(path string) (guidance.LastStop, bool)
	// OpenLog opens the engine log at path for appending, never through a
	// link.
	OpenLog(path string) (*os.File, error)
}

// StarterDeps are the starter's reach into the machine; tests replace them.
type StarterDeps struct {
	// OS is the machine's files the starter reads and makes.
	OS StarterOS
	// Owner is the uid that owns path.
	Owner func(path string) (int, error)
	// Launch runs exe with args detached, its output to logFile.
	Launch func(exe string, args []string, logFile *os.File) error
	// Answers reports whether the socket answers.
	Answers func(socket string) bool
	// Wait is how long start waits for the socket to answer.
	Wait time.Duration
	// Now is the clock for the start hold-off; tests replace it.
	Now func() time.Time
}

// NewStarter returns what starts the engine for configPath when a
// message finds it down, and the text of the last failure ("" when the last
// try worked or there was none). start is nil when auto-start does not
// apply: no config, a service-mode config, or a config file another user
// owns. The engine then keeps today's engine-down answer. It panics on a
// nil d.OS.
func NewStarter(h StarterHost, d StarterDeps, configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	if d.OS == nil {
		panic("engine: the starter needs the machine's files (StarterDeps.OS)")
	}
	// A root shim never starts an engine: root is not a same-user engine.
	if cfg == nil || cfg.Service() || euid == 0 {
		return nil, nil
	}
	if uid, err := d.Owner(configPath); err != nil || uid != euid {
		return nil, nil
	}
	s := &starter{host: h, deps: d, configPath: configPath, socket: socket, cfg: *cfg, exe: exe, log: log}
	return s.start, s.failure
}

type starter struct {
	host       StarterHost
	deps       StarterDeps
	configPath string
	socket     string
	cfg        config.Config
	exe        string
	log        *slog.Logger

	mu     sync.Mutex
	failed string
	// stuck: the last wait ended with the engine's lock still held.
	stuck bool
}

func (s *starter) stateDir() string { return s.cfg.StateDirFor(runtime.GOOS) }

func (s *starter) failure() string {
	if _, _, holding := s.holdOff(); holding {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == "" {
		return ""
	}
	return fmt.Sprintf("basalt mcp could not start the engine: %s. Its log is %s.", s.failed, filepath.Join(s.stateDir(), engineLogName))
}

func (s *starter) now() time.Time {
	if s.deps.Now != nil {
		return s.deps.Now()
	}
	return time.Now()
}

// holdOff reports whether last-stop.json still holds off a new start.
func (s *starter) holdOff() (until time.Time, stop guidance.LastStop, ok bool) {
	stop, ok = s.deps.OS.ReadLastStop(filepath.Join(s.stateDir(), LastStopFile))
	if !ok {
		return time.Time{}, guidance.LastStop{}, false
	}
	until, ok = s.host.LastStopStartHoldOffUntil(servicespec.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, s.configPath, s.now())
	return until, stop, ok
}

func (s *starter) record(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = ""
	if err != nil {
		s.failed = err.Error()
		s.log.Warn("basalt mcp could not start the engine", "err", err)
	}
	return err
}

// start follows the steps of the contract: the start lock, the engine lock
// again under it, a supervisor holding supervise.lock, the last-stop
// hold-off, the log, the detached supervisor, and the wait for the agent's
// socket to answer. Only the text of the last failure is remembered
// between calls, and whether an engine that holds its lock failed to serve
// this socket (then the next calls look once and do not wait again until
// that engine is gone).
func (s *starter) start(ctx context.Context) error {
	// A config that is gone (the engine removed itself after a removal on
	// the connect page) starts nothing and makes no folder: the removed
	// tree never comes back, and status answers REMOVED.
	if _, err := s.deps.Owner(s.configPath); err != nil {
		return s.record(err)
	}
	// An update drops empty folders and resets modes; these are ours.
	if err := s.deps.OS.MakeDirs(s.cfg.SocketDir, PrivateDirMode); err != nil {
		return s.record(err)
	}
	if err := s.deps.OS.MakeDirs(s.stateDir(), PrivateDirMode); err != nil {
		return s.record(err)
	}
	release, err := lockStart(s.deps.OS, filepath.Join(s.cfg.SocketDir, startLockName))
	if errors.Is(err, config.ErrLocked) {
		return s.waitSocket(ctx) // another shim is starting it
	}
	if err != nil {
		return s.record(err)
	}
	defer release()

	if s.deps.OS.LockHolderRuns(LockPath(s.cfg.SocketDir)) {
		return s.engineRuns(ctx)
	}
	// A supervisor may hold its lock before its child takes the engine
	// lock (it is starting, or waiting to restart). Do not launch another.
	held, err := lockHeld(s.deps.OS, filepath.Join(s.cfg.SocketDir, SuperviseLock))
	if err != nil {
		return s.record(err)
	}
	if held {
		return s.waitSocket(ctx)
	}
	s.forgetStuck()
	if until, stop, ok := s.holdOff(); ok {
		// The shim treats an error as "try the socket once, do not wait".
		return fmt.Errorf("the supervisor gave up at %s: %s; the next try is at %s", stop.At.UTC().Format(time.RFC3339), stop.Reason, until.UTC().Format(time.RFC3339))
	}
	if err := s.deps.OS.StatPath(s.exe); err != nil {
		return s.record(fmt.Errorf("the basalt binary %s is gone", s.exe))
	}
	logFile, err := s.deps.OS.OpenLog(filepath.Join(s.stateDir(), engineLogName))
	if err != nil {
		return s.record(fmt.Errorf("open the engine log: %w", err))
	}
	defer logFile.Close()
	if err := s.deps.Launch(s.exe, []string{engineCommand, "--supervise", configFlag, s.configPath, "--started-by", StartedByMCP}, logFile); err != nil {
		return s.record(fmt.Errorf("start %s: %w", s.exe, err))
	}
	return s.waitSocket(ctx)
}

// engineRuns is start for an engine that holds its lock: it may still be
// coming up, or it may never serve this agent's socket (an agent added to
// the config after it started). After one wait that ended that way, a
// later call looks once.
func (s *starter) engineRuns(ctx context.Context) error {
	s.mu.Lock()
	stuck, failed := s.stuck, s.failed
	s.mu.Unlock()
	if !stuck {
		return s.waitSocket(ctx)
	}
	if s.deps.Answers(s.socket) {
		s.forgetStuck()
		return s.record(nil)
	}
	return errors.New(failed)
}

func (s *starter) forgetStuck() {
	s.mu.Lock()
	s.stuck = false
	s.mu.Unlock()
}

// waitSocket waits for the agent's socket to answer, up to the wait; the
// reason it gives when it never does is named in status.
func (s *starter) waitSocket(ctx context.Context) error {
	deadline := time.NewTimer(s.deps.Wait)
	defer deadline.Stop()
	tick := time.NewTicker(startPoll)
	defer tick.Stop()
	for {
		if s.deps.Answers(s.socket) {
			s.forgetStuck()
			return s.record(nil)
		}
		select {
		case <-ctx.Done():
			return s.record(ctx.Err())
		case <-deadline.C:
			up := s.deps.OS.LockHolderRuns(LockPath(s.cfg.SocketDir))
			s.mu.Lock()
			s.stuck = up
			s.mu.Unlock()
			return s.record(fmt.Errorf("the engine did not answer on %s within %s", s.socket, s.deps.Wait))
		case <-tick.C:
		}
	}
}

// lockHeld reports whether another process holds an exclusive flock on
// path, without keeping the lock. A missing file is not held.
func lockHeld(o StarterOS, path string) (bool, error) {
	release, err := o.LockFile(path)
	if errors.Is(err, config.ErrLocked) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	release()
	return false, nil
}

// lockStart is o.LockFile, trying again a few times when the folder
// another shim has just made is not visible yet (two shims racing to make
// it on a fresh start).
func lockStart(o StarterOS, path string) (func(), error) {
	const tries = 5
	var release func()
	var err error
	for range tries {
		if release, err = o.LockFile(path); !errors.Is(err, os.ErrNotExist) {
			return release, err
		}
		time.Sleep(startPoll / 5)
	}
	return release, err
}
