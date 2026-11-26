package app

import (
	"context"
	"log/slog"
	"os/exec"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// startedByHand is the --started-by of an engine a person started.
const startedByHand = "hand"

// childStopWait is how long a child gets after SIGTERM before SIGKILL.
const childStopWait = 30 * time.Second

// childStarter runs the engine as startedFrom engine --config ... --started-by ...
// with this process's output, after resolving startedFrom again. A child
// that stays up for engine.FastCrash clears the last give-up; one that fails
// because another engine holds the lock reports engine.ErrAnotherEngine.
func childStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return func(ctx context.Context, startedBy string) (func() error, error) {
		exe, err := engine.ResolveSuperviseBinary(engineos.OS{}, startedFrom)
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
		stable := time.AfterFunc(engine.FastCrash, func() { engine.ClearLastStop(engineos.OS{}, stateDir, log) })
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
