package enginecli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// RunSupervise is basalt engine --supervise: one supervisor per config,
// restarting the engine as a child of this process.
func RunSupervise(ctx context.Context, configPath, startedBy string, io cli.Stdio, h cli.Machine,
	m Host, eh engine.Host, t engine.Terminal, bw engine.BinaryWatch,
) int {
	cfg, err := engine.SuperviseConfig(t, h.Euid(), configPath)
	if err != nil {
		return m.Fail(io.Err, "engine", err)
	}
	startedFrom, err := engine.SuperviseBinaryPath(bw)
	if err != nil {
		return m.Fail(io.Err, "engine", err)
	}
	// An update can drop empty folders; the engine makes its own too.
	if err := os.MkdirAll(cfg.SocketDir, engine.PrivateDirMode); err != nil {
		return m.Fail(io.Err, "engine", err)
	}
	release, err := config.LockFile(filepath.Join(cfg.SocketDir, engine.SuperviseLock))
	if errors.Is(err, config.ErrLocked) {
		_, _ = fmt.Fprintln(io.Err, "basalt engine: another basalt engine --supervise runs for this config")
		return cli.ExitOK
	}
	if err != nil {
		return m.Fail(io.Err, "engine", err)
	}
	defer release()

	log := m.EngineLog(io.Err)
	stateDir := cfg.StateDirFor(runtime.GOOS)
	lockPath := engine.LockPath(cfg.SocketDir)
	o := engine.SuperviseOptions{
		FirstStartedBy: startedBy,
		Start:          m.ChildStarter(startedFrom, configPath, lockPath, stateDir, io, log),
		Sleep:          cli.SleepCtx,
		Now:            time.Now,
		Log:            log,
		LastStop: func(reason string) {
			engine.WriteLastStop(eh, t, stateDir, reason, configPath, time.Now(), log)
		},
	}
	if err := engine.Supervise(ctx, o); err != nil {
		return m.Fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}
