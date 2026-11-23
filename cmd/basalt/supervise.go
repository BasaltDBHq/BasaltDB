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
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// startedByHand is the --started-by of an engine a person started.
const startedByHand = "hand"

// childStopWait is how long a child gets after SIGTERM before SIGKILL.
const childStopWait = 30 * time.Second

// runSupervise is basalt engine --supervise: one supervisor per config,
// restarting the engine as a child of this process.
func runSupervise(ctx context.Context, configPath, startedBy string, io cli.Stdio, h cli.Machine) int {
	cfg, err := engine.SuperviseConfig(engineTerminal{}, h.Euid(), configPath)
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	startedFrom, err := engine.SuperviseBinaryPath(app.BinaryWatch{})
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	// An update can drop empty folders; the engine makes its own too.
	if err := os.MkdirAll(cfg.SocketDir, engine.PrivateDirMode); err != nil {
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
		LastStop: func(reason string) {
			engine.WriteLastStop(engineHost{}, engineTerminal{}, stateDir, reason, configPath, time.Now(), log)
		},
	}
	if err := engine.Supervise(ctx, o); err != nil {
		return fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}

// childStarter runs the engine as startedFrom engine --config ... --started-by ...
// with this process's output, after resolving startedFrom again. A child
// that stays up for engine.FastCrash clears the last give-up; one that fails
// because another engine holds the lock reports engine.ErrAnotherEngine.
func childStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return func(ctx context.Context, startedBy string) (func() error, error) {
		exe, err := engine.ResolveSuperviseBinary(startedFrom)
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
		stable := time.AfterFunc(engine.FastCrash, func() { engine.ClearLastStop(stateDir, log) })
		return func() error {
			err := cmd.Wait()
			stable.Stop()
			if err != nil && ctx.Err() == nil {
				// The child has exited, so a live holder is another engine.
				if engine.AnotherEngineRuns(engineTerminal{}, lockPath) {
					return engine.ErrAnotherEngine
				}
			}
			return err
		}, nil
	}
}
