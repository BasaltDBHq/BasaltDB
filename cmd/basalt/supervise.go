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

// startedByHand is the --started-by of an engine a person started.
const startedByHand = "hand"

// childStopWait is how long a child gets after SIGTERM before SIGKILL.
const childStopWait = 30 * time.Second

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
	release, err := config.LockFile(filepath.Join(cfg.SocketDir, engine.SuperviseLock))
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
	o := engine.SuperviseOptions{
		FirstStartedBy: startedBy,
		Start:          childStarter(startedFrom, configPath, lockPath, stateDir, io, log),
		Sleep:          cli.SleepCtx,
		Now:            time.Now,
		Log:            log,
		LastStop:       func(reason string) { writeLastStop(stateDir, reason, configPath, time.Now(), log) },
	}
	if err := engine.Supervise(ctx, o); err != nil {
		return fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}

// superviseConfig is the config the supervisor needs (its socket and state
// folders): the config file's, or, for a service engine whose config does
// not exist yet, the defaults its child waits with (engine.WaitsForConfig).
func superviseConfig(euid int, configPath string) (config.Config, error) {
	if engine.WaitsForConfig(engineTerminal{}, euid, configPath) {
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
// engine.BinaryGoneError.
func resolveSuperviseBinary(startedFrom string) (string, error) {
	if _, err := os.Stat(startedFrom); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", &engine.BinaryGoneError{Path: startedFrom}
		}
		return "", err
	}
	return startedFrom, nil
}

// childStarter runs the engine as startedFrom engine --config ... --started-by ...
// with this process's output, after resolving startedFrom again. A child
// that stays up for engine.FastCrash clears the last give-up; one that fails
// because another engine holds the lock reports engine.ErrAnotherEngine.
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
		stable := time.AfterFunc(engine.FastCrash, func() { clearLastStop(stateDir, log) })
		return func() error {
			err := cmd.Wait()
			stable.Stop()
			if err != nil && ctx.Err() == nil {
				// The child has exited, so a live holder is another engine.
				if anotherEngineRuns(lockPath) {
					return engine.ErrAnotherEngine
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
		err = cli.WriteFileAtomic(filepath.Join(stateDir, engine.LastStopFile), raw)
	}
	if err != nil {
		log.Warn("could not record why the engine stopped", "err", err)
	}
}

func clearLastStop(stateDir string, log *slog.Logger) {
	if err := os.Remove(filepath.Join(stateDir, engine.LastStopFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
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
