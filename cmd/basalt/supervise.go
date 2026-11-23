package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/app/binwatch"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// The values of --started-by: who started this engine.
const (
	startedByHand  = "hand"
	startedByMCP   = "mcp"
	startedByCrash = "crash"
)

const (
	// fastCrash is how long a child must stay up for its exit not to count
	// as a fast crash.
	fastCrash = 10 * time.Second
	// maxFastCrashes in a row make the supervisor give up.
	maxFastCrashes = 5
	// childStopWait is how long a child gets after SIGTERM before SIGKILL.
	childStopWait = 30 * time.Second
	lastStopFile  = engine.LastStopFile
	superviseLock = "supervise.lock"
)

// restartBackoff is the wait before restart n (counting from the first
// restart after a run of at least fastCrash); it stays at the last value.
var restartBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}

// errAnotherEngine is what a child's wait returns when the child failed
// because another engine holds the config's engine lock.
var errAnotherEngine = errors.New("another engine already runs for this config")

// binaryGoneError is a crash restart whose binary path is gone: the
// supervisor records why and stops instead of looping on a missing file.
type binaryGoneError struct{ path string }

func (e *binaryGoneError) Error() string {
	return fmt.Sprintf("the basalt binary %s is gone", e.path)
}

type superviseOptions struct {
	// firstStartedBy is the --started-by of the first child; every restart
	// is startedByCrash.
	firstStartedBy string
	// start runs one child and returns what waits for its exit.
	start func(ctx context.Context, startedBy string) (wait func() error, err error)
	// sleep waits d, and is false when ctx is done first.
	sleep func(ctx context.Context, d time.Duration) bool
	now   func() time.Time
	log   *slog.Logger
	// lastStop records why the supervisor gave up.
	lastStop func(reason string)
}

// supervise runs children until one stops cleanly, ctx is done, the
// children keep crashing, another engine runs, or the binary path is
// gone. The error is the reason it gave up.
func supervise(ctx context.Context, o superviseOptions) error {
	startedBy := o.firstStartedBy
	fast, restarts := 0, 0
	for {
		began := o.now()
		err := runChild(ctx, o, startedBy)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil //nolint:nilerr // a stop signal ends the child; that is the clean stop, not a crash
		}
		if errors.Is(err, errAnotherEngine) {
			o.log.Info(errAnotherEngine.Error())
			return nil
		}
		var gone *binaryGoneError
		if errors.As(err, &gone) {
			reason := gone.Error()
			o.log.Error("giving up", "reason", reason)
			o.lastStop(reason)
			return err
		}
		if o.now().Sub(began) < fastCrash {
			fast++
		} else {
			fast, restarts = 0, 0
		}
		if fast >= maxFastCrashes {
			reason := fmt.Sprintf("the engine crashed %d times within %s; last: %v", maxFastCrashes, fastCrash, err)
			o.log.Error("giving up", "reason", reason)
			o.lastStop(reason)
			return errors.New(reason)
		}
		wait := restartBackoff[min(restarts, len(restartBackoff)-1)]
		restarts++
		o.log.Warn("the engine exited; restarting it", "err", err, "in", wait)
		if !o.sleep(ctx, wait) {
			return nil
		}
		startedBy = startedByCrash
	}
}

func runChild(ctx context.Context, o superviseOptions, startedBy string) error {
	wait, err := o.start(ctx, startedBy)
	if err != nil {
		return err
	}
	return wait()
}

// runSupervise is basalt engine --supervise: one supervisor per config,
// restarting the engine as a child of this process.
func runSupervise(ctx context.Context, configPath, startedBy string, io cli.Stdio, h cli.Machine) int {
	cfg, err := superviseConfig(h.Euid(), configPath)
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	startedFrom, err := superviseBinaryPath()
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	// An update can drop empty folders; the engine makes its own too.
	if err := os.MkdirAll(cfg.SocketDir, privateDirMode); err != nil {
		return fail(io.Err, "engine", err)
	}
	release, err := config.LockFile(filepath.Join(cfg.SocketDir, superviseLock))
	if errors.Is(err, config.ErrLocked) {
		_, _ = fmt.Fprintln(io.Err, "basalt engine: another basalt engine --supervise runs for this config")
		return cli.ExitOK
	}
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	defer release()

	log := engineLog(io.Err)
	stateDir := cfg.StateDirFor(runtime.GOOS)
	lockPath := engine.LockPath(cfg.SocketDir)
	o := superviseOptions{
		firstStartedBy: startedBy,
		start:          childStarter(startedFrom, configPath, lockPath, stateDir, io, log),
		sleep:          cli.SleepCtx,
		now:            time.Now,
		log:            log,
		lastStop:       func(reason string) { writeLastStop(stateDir, reason, configPath, time.Now(), log) },
	}
	if err := supervise(ctx, o); err != nil {
		return fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}

// superviseConfig is the config the supervisor needs (its socket and state
// folders): the config file's, or, for a service engine whose config does
// not exist yet, the defaults its child waits with (waitsForConfig).
func superviseConfig(euid int, configPath string) (config.Config, error) {
	if waitsForConfig(euid, configPath) {
		return config.Config{
			SocketDir: config.DefaultSocketDir(runtime.GOOS), StateDir: config.DefaultStateDir(runtime.GOOS),
		}, nil
	}
	return cli.LoadEngineConfigAs(appShell{}, euid, configPath)
}

const privateDirMode = 0o700

// superviseBinaryPath is the path the supervisor was started from: a
// crash restart resolves it again, so a new file at the same path is run
// and a missing one is not looped on.
func superviseBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return binwatch.ExecPath(os.Args[0], exec.LookPath, func() (string, error) { return exe, nil }, binwatch.OS{}.Stat)
}

// resolveSuperviseBinary looks up startedFrom again; a missing file is
// binaryGoneError.
func resolveSuperviseBinary(startedFrom string) (string, error) {
	if _, err := os.Stat(startedFrom); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", &binaryGoneError{path: startedFrom}
		}
		return "", err
	}
	return startedFrom, nil
}

// childStarter runs the engine as startedFrom engine --config ... --started-by ...
// with this process's output, after resolving startedFrom again. A child
// that stays up for fastCrash clears the last give-up; one that fails
// because another engine holds the lock reports errAnotherEngine.
func childStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return func(ctx context.Context, startedBy string) (func() error, error) {
		exe, err := resolveSuperviseBinary(startedFrom)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, exe, "engine", "--config", configPath, "--started-by", startedBy)
		cmd.Stdout, cmd.Stderr = io.Out, io.Err
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = childStopWait
		prepareSuperviseChild(cmd)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		stable := time.AfterFunc(fastCrash, func() { clearLastStop(stateDir, log) })
		return func() error {
			err := cmd.Wait()
			stable.Stop()
			if err != nil && ctx.Err() == nil {
				// The child has exited, so a live holder is another engine.
				if anotherEngineRuns(lockPath) {
					return errAnotherEngine
				}
			}
			return err
		}, nil
	}
}

func writeLastStop(stateDir, reason, configPath string, at time.Time, log *slog.Logger) {
	raw, err := json.Marshal(app.LastStopRecord{Reason: reason, At: at.UTC(), EngineSHA256: app.LastStopHashEngineJSON(configPath)})
	if err == nil {
		err = os.MkdirAll(stateDir, privateDirMode)
	}
	if err == nil {
		err = cli.WriteFileAtomic(filepath.Join(stateDir, lastStopFile), raw)
	}
	if err != nil {
		log.Warn("could not record why the engine stopped", "err", err)
	}
}

func clearLastStop(stateDir string, log *slog.Logger) {
	if err := os.Remove(filepath.Join(stateDir, lastStopFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warn("could not remove the record of why the engine stopped", "err", err)
	}
}

// anotherEngineRuns is true when the engine lock is held at every one of a
// few looks. A real engine holds it all the time; a probe by someone else
// (basalt status, a starting basalt mcp) holds it for a moment and reads as
// a holder, so one look that finds it free means no engine runs.
func anotherEngineRuns(lockPath string) bool {
	return cli.HeldAtEveryLook(func() bool {
		_, up, _ := pidlock.Running(lockPath)
		return up
	}, time.Sleep)
}
