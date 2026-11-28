package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// The values of --started-by a supervisor gives its children.
const (
	StartedByMCP   = "mcp"
	StartedByCrash = "crash"
	// StartedByService is the engine the OS service manager started: the
	// unit passes it.
	StartedByService = "service"
)

const (
	// FastCrash is how long a child must stay up for its exit not to count
	// as a fast crash.
	FastCrash = 10 * time.Second
	// maxFastCrashes in a row make the supervisor give up.
	maxFastCrashes = 5
	// SuperviseLock is the supervisor's lock file in the socket directory:
	// one supervisor per config.
	SuperviseLock = "supervise.lock"
)

// restartBackoff is the wait before restart n (counting from the first
// restart after a run of at least FastCrash); it stays at the last value.
var restartBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}

// ErrAnotherEngine is what a child's wait returns when the child failed
// because another engine holds the config's engine lock.
var ErrAnotherEngine = errors.New("another engine already runs for this config")

// BinaryGoneError is a crash restart whose binary path is gone: the
// supervisor records why and stops instead of looping on a missing file.
type BinaryGoneError struct{ Path string }

func (e *BinaryGoneError) Error() string {
	return fmt.Sprintf("the basalt binary %s is gone", e.Path)
}

// SuperviseOptions are what Supervise runs children with.
type SuperviseOptions struct {
	// FirstStartedBy is the --started-by of the first child; every restart
	// is StartedByCrash.
	FirstStartedBy string
	// Start runs one child and returns what waits for its exit.
	Start func(ctx context.Context, startedBy string) (wait func() error, err error)
	// Sleep waits d, and is false when ctx is done first.
	Sleep func(ctx context.Context, d time.Duration) bool
	Now   func() time.Time
	Log   *slog.Logger
	// LastStop records why the supervisor gave up.
	LastStop func(reason string)
}

// Supervise runs children until one stops cleanly, ctx is done, the
// children keep crashing, another engine runs, or the binary path is
// gone. The error is the reason it gave up.
func Supervise(ctx context.Context, o SuperviseOptions) error {
	startedBy := o.FirstStartedBy
	fast, restarts := 0, 0
	for {
		began := o.Now()
		err := runChild(ctx, o, startedBy)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil //nolint:nilerr // a stop signal ends the child; that is the clean stop, not a crash
		}
		if errors.Is(err, ErrAnotherEngine) {
			o.Log.Info(ErrAnotherEngine.Error())
			return nil
		}
		var gone *BinaryGoneError
		if errors.As(err, &gone) {
			reason := gone.Error()
			o.Log.Error("giving up", "reason", reason)
			o.LastStop(reason)
			return err
		}
		if o.Now().Sub(began) < FastCrash {
			fast++
		} else {
			fast, restarts = 0, 0
		}
		if fast >= maxFastCrashes {
			reason := fmt.Sprintf("the engine crashed %d times within %s; last: %v", maxFastCrashes, FastCrash, err)
			o.Log.Error("giving up", "reason", reason)
			o.LastStop(reason)
			return errors.New(reason)
		}
		wait := restartBackoff[min(restarts, len(restartBackoff)-1)]
		restarts++
		o.Log.Warn("the engine exited; restarting it", "err", err, "in", wait)
		if !o.Sleep(ctx, wait) {
			return nil
		}
		startedBy = StartedByCrash
	}
}

func runChild(ctx context.Context, o SuperviseOptions, startedBy string) error {
	wait, err := o.Start(ctx, startedBy)
	if err != nil {
		return err
	}
	return wait()
}

// configFlag is the engine's flag that names its config file.
const configFlag = "--config"

// ChildDeps is what ChildStarter starts a supervised engine with: the
// machine its binary is looked up on, the terminal that tells whether
// another engine holds the lock, and Start, which runs a process and
// returns the wait for its exit.
type ChildDeps struct {
	Machine  Machine
	Terminal Terminal
	Start    func(ctx context.Context, exe string, args []string, out, errw io.Writer) (wait func() error, err error)
}

// ChildStarter runs the engine as startedFrom engine --config ...
// --started-by ... with out and errw, after resolving startedFrom again. A
// child that stays up for FastCrash clears the last give-up in stateDir;
// one that fails because another engine holds lockPath reports
// ErrAnotherEngine.
func ChildStarter(d ChildDeps, startedFrom, configPath, lockPath, stateDir string, out, errw io.Writer, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return func(ctx context.Context, startedBy string) (func() error, error) {
		exe, err := ResolveSuperviseBinary(d.Machine, startedFrom)
		if err != nil {
			return nil, err
		}
		wait, err := d.Start(ctx, exe, []string{engineCommand, configFlag, configPath, startedByFlag, startedBy}, out, errw)
		if err != nil {
			return nil, err
		}
		stable := time.AfterFunc(FastCrash, func() { ClearLastStop(d.Machine, stateDir, log) })
		return func() error {
			err := wait()
			stable.Stop()
			if err != nil && ctx.Err() == nil {
				// The child has exited, so a live holder is another engine.
				if AnotherEngineRuns(d.Terminal, lockPath) {
					return ErrAnotherEngine
				}
			}
			return err
		}, nil
	}
}
