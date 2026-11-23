//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

const (
	startLockName = "start.lock"
	engineLogName = "engine.log"
	startPoll     = 50 * time.Millisecond
	dialTimeout   = 200 * time.Millisecond
)

// starterDeps are the starter's reach into the machine; tests replace them.
type starterDeps struct {
	// owner is the uid that owns path.
	owner func(path string) (int, error)
	// launch runs exe with args detached, its output to logFile.
	launch func(exe string, args []string, logFile *os.File) error
	// answers reports whether the socket answers.
	answers func(socket string) bool
	// wait is how long start waits for the socket to answer.
	wait time.Duration
	// now is the clock for the start hold-off; tests replace it.
	now func() time.Time
}

func osStarterDeps() starterDeps {
	return starterDeps{owner: cli.PathOwner, launch: launchDetached, answers: socketAnswers, wait: shim.DefaultStartWait, now: time.Now}
}

func socketAnswers(socket string) bool {
	c, err := net.DialTimeout("unix", socket, dialTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// launchDetached starts exe args in a new session with no stdin and
// logFile for output, and lets it go: it outlives this process.
func launchDetached(exe string, args []string, logFile *os.File) error {
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Dir = "/" // the config path is absolute; nothing depends on the shim's folder
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap it if it exits while this process lives
	return nil
}

// engineStarter is the starter basalt mcp gives the shim (see
// newEngineStarter) with the real machine.
func engineStarter(configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	return newEngineStarter(osStarterDeps(), configPath, socket, cfg, euid, exe, log)
}

// newEngineStarter returns what starts the engine for configPath when a
// message finds it down, and the text of the last failure ("" when the last
// try worked or there was none). start is nil when auto-start does not
// apply: no config, a service-mode config, or a config file another user
// owns. The engine then keeps today's engine-down answer.
func newEngineStarter(d starterDeps, configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	// A root shim never starts an engine: root is not a same-user engine.
	if cfg == nil || cfg.Service() || euid == 0 {
		return nil, nil
	}
	if uid, err := d.owner(configPath); err != nil || uid != euid {
		return nil, nil
	}
	s := &starter{deps: d, configPath: configPath, socket: socket, cfg: *cfg, exe: exe, log: log}
	return s.start, s.failure
}

type starter struct {
	deps       starterDeps
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
	if s.deps.now != nil {
		return s.deps.now()
	}
	return time.Now()
}

// holdOff reports whether last-stop.json still holds off a new start.
func (s *starter) holdOff() (until time.Time, stop guidance.LastStop, ok bool) {
	stop, ok = agent.ReadLastStop(s.stateDir())
	if !ok {
		return time.Time{}, guidance.LastStop{}, false
	}
	until, ok = app.LastStopStartHoldOffUntil(app.LastStopRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, s.configPath, s.now())
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
	// An update drops empty folders and resets modes; these are ours.
	if err := os.MkdirAll(s.cfg.SocketDir, engine.PrivateDirMode); err != nil {
		return s.record(err)
	}
	if err := os.MkdirAll(s.stateDir(), engine.PrivateDirMode); err != nil {
		return s.record(err)
	}
	release, err := lockStart(filepath.Join(s.cfg.SocketDir, startLockName))
	if errors.Is(err, config.ErrLocked) {
		return s.waitSocket(ctx) // another shim is starting it
	}
	if err != nil {
		return s.record(err)
	}
	defer release()

	if _, up, _ := pidlock.Running(engine.LockPath(s.cfg.SocketDir)); up {
		return s.engineRuns(ctx)
	}
	// A supervisor may hold its lock before its child takes the engine
	// lock (it is starting, or waiting to restart). Do not launch another.
	held, err := lockHeld(filepath.Join(s.cfg.SocketDir, engine.SuperviseLock))
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
	if _, err := os.Stat(s.exe); err != nil {
		return s.record(fmt.Errorf("the basalt binary %s is gone", s.exe))
	}
	logFile, err := os.OpenFile(filepath.Join(s.stateDir(), engineLogName), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, config.FileMode)
	if err != nil {
		return s.record(fmt.Errorf("open the engine log: %w", err))
	}
	defer logFile.Close()
	if err := s.deps.launch(s.exe, []string{"engine", "--supervise", "--config", s.configPath, "--started-by", engine.StartedByMCP}, logFile); err != nil {
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
	if s.deps.answers(s.socket) {
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
	deadline := time.NewTimer(s.deps.wait)
	defer deadline.Stop()
	tick := time.NewTicker(startPoll)
	defer tick.Stop()
	for {
		if s.deps.answers(s.socket) {
			s.forgetStuck()
			return s.record(nil)
		}
		select {
		case <-ctx.Done():
			return s.record(ctx.Err())
		case <-deadline.C:
			_, up, _ := pidlock.Running(engine.LockPath(s.cfg.SocketDir))
			s.mu.Lock()
			s.stuck = up
			s.mu.Unlock()
			return s.record(fmt.Errorf("the engine did not answer on %s within %s", s.socket, s.deps.wait))
		case <-tick.C:
		}
	}
}

// lockHeld reports whether another process holds an exclusive flock on
// path, without keeping the lock. A missing file is not held.
func lockHeld(path string) (bool, error) {
	release, err := config.LockFile(path)
	if errors.Is(err, config.ErrLocked) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	release()
	return false, nil
}

// lockStart is config.LockFile, trying again a few times when the folder
// another shim has just made is not visible yet (two shims racing to make
// it on a fresh start).
func lockStart(path string) (func(), error) {
	const tries = 5
	var release func()
	var err error
	for range tries {
		if release, err = config.LockFile(path); !errors.Is(err, os.ErrNotExist) {
			return release, err
		}
		time.Sleep(startPoll / 5)
	}
	return release, err
}
