//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/shim"
)

const (
	startLockName = "start.lock"
	engineLogName = "engine.log"
	startPoll     = 50 * time.Millisecond
)

// starterDeps are the starter's reach into the machine; tests replace them.
type starterDeps struct {
	// owner is the uid that owns path.
	owner func(path string) (int, error)
	// launch runs exe with args detached, its output to logFile.
	launch func(exe string, args []string, logFile *os.File) error
	// wait is how long start waits for the engine to take its lock.
	wait time.Duration
}

func osStarterDeps() starterDeps {
	return starterDeps{owner: pathOwner, launch: launchDetached, wait: shim.DefaultStartWait}
}

func pathOwner(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no owner for " + path)
	}
	return int(st.Uid), nil
}

// launchDetached starts exe args in a new session with no stdin and
// logFile for output, and lets it go: it outlives this process.
func launchDetached(exe string, args []string, logFile *os.File) error {
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// engineStarter is the starter basalt mcp gives the shim (see
// newEngineStarter) with the real machine.
func engineStarter(configPath string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	return newEngineStarter(osStarterDeps(), configPath, cfg, euid, exe, log)
}

// newEngineStarter returns what starts the engine for configPath when a
// message finds it down, and the text of the last failure ("" when the last
// try worked or there was none). start is nil when auto-start does not
// apply: no config, a service-mode config, or a config file another user
// owns. The engine then keeps today's engine-down answer.
func newEngineStarter(d starterDeps, configPath string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	// A root shim never starts an engine: root is not a same-user engine.
	if cfg == nil || cfg.Service() || euid == 0 {
		return nil, nil
	}
	if uid, err := d.owner(configPath); err != nil || uid != euid {
		return nil, nil
	}
	s := &starter{deps: d, configPath: configPath, cfg: *cfg, exe: exe, log: log}
	return s.start, s.failure
}

type starter struct {
	deps       starterDeps
	configPath string
	cfg        config.Config
	exe        string
	log        *slog.Logger

	mu     sync.Mutex
	failed string
}

func (s *starter) stateDir() string { return s.cfg.StateDirFor(runtime.GOOS) }

func (s *starter) failure() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == "" {
		return ""
	}
	return fmt.Sprintf("basalt mcp could not start the engine: %s. Its log is %s.", s.failed, filepath.Join(s.stateDir(), engineLogName))
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
// again under it, the log, the detached supervisor, and the wait for the
// engine to take its lock (the shim then waits for its socket). Nothing
// is remembered between calls but the text of the last failure.
func (s *starter) start(ctx context.Context) error {
	// An update drops empty folders and resets modes; these are ours.
	if err := os.MkdirAll(s.cfg.SocketDir, privateDirMode); err != nil {
		return s.record(err)
	}
	if err := os.MkdirAll(s.stateDir(), privateDirMode); err != nil {
		return s.record(err)
	}
	release, err := lockStart(filepath.Join(s.cfg.SocketDir, startLockName))
	if errors.Is(err, config.ErrLocked) {
		return nil // another shim is starting it; the shim waits for the socket
	}
	if err != nil {
		return s.record(err)
	}
	defer release()

	lockPath := engine.LockPath(s.cfg.SocketDir)
	if _, up, _ := server.Running(lockPath); up {
		return s.record(nil)
	}
	if _, err := os.Stat(s.exe); err != nil {
		return s.record(fmt.Errorf("the basalt binary %s is gone", s.exe))
	}
	logFile, err := os.OpenFile(filepath.Join(s.stateDir(), engineLogName), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, config.FileMode)
	if err != nil {
		return s.record(fmt.Errorf("open the engine log: %w", err))
	}
	defer logFile.Close()
	if err := s.deps.launch(s.exe, []string{"engine", "--supervise", "--config", s.configPath, "--started-by", startedByMCP}, logFile); err != nil {
		return s.record(fmt.Errorf("start %s: %w", s.exe, err))
	}
	deadline := time.NewTimer(s.deps.wait)
	defer deadline.Stop()
	tick := time.NewTicker(startPoll)
	defer tick.Stop()
	for {
		if _, up, _ := server.Running(lockPath); up {
			return s.record(nil)
		}
		select {
		case <-ctx.Done():
			return s.record(ctx.Err())
		case <-deadline.C:
			return s.record(fmt.Errorf("the engine did not start within %s", s.deps.wait))
		case <-tick.C:
		}
	}
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
