package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/status/in/statusmcp"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/lib/logredact"
)

// runGuarded runs the command line and turns a panic into a saved crash
// report, one line on stderr and exit code 1.
func runGuarded(ctx context.Context, args []string, std cli.Stdio) int {
	return enginecli.Guarded(engineCLIHost{}, engineHost{}, engineTerminal{}, args, std, func() int { return run(ctx, args, std) })
}

// engineCLIHost is enginecli.Host for the command table, through app.
type engineCLIHost struct{}

func (engineCLIHost) CommandName(args []string) string { return cli.CommandName(args, commands()) }

func (engineCLIHost) Fail(w io.Writer, name string, err error) int { return cli.Fail(w, name, err) }

func (engineCLIHost) ChildStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return engine.ChildStarter(engine.ChildDeps{Machine: engineos.OS{}, Terminal: engineTerminal{}, Start: engineos.StartChild}, startedFrom, configPath, lockPath, stateDir, io.Out, io.Err, log)
}

func (engineCLIHost) RunServiceAt(ctx context.Context, args []string, io cli.Stdio, configPath string) int {
	return runServiceAt(ctx, args, io, configPath)
}

func (engineCLIHost) EngineLog(w io.Writer) *slog.Logger {
	return slog.New(logredact.NewTextHandler(w, nil))
}

func (engineCLIHost) EngineDown(name, configPath string, log *slog.Logger) (statusmcp.EngineDown, error) {
	return statusmcp.LoadEngineDown(name, configPath, AgentServiceManager(), agentEngineHost(), log)
}

func (engineCLIHost) NewEngineDownServer(down statusmcp.EngineDown) shim.Fallback {
	return statusmcp.NewServer(down, Instructions)
}

func (engineCLIHost) SocketAgents(dir string) []string {
	return engine.SocketAgents(engineos.OS{}, dir)
}

// engineHost is engine.Host through app and the machine.
type engineHost struct{ osHost }

func (engineHost) NewRecorder() engine.Recorder {
	return crash.Recorder{Version: buildinfo.Version, Scrub: crash.OSScrubber(), Now: time.Now}
}

func (engineHost) LastStopHashEngineJSON(path string) string { return laststop.HashEngineJSON(path) }

func (engineHost) LastStopStartHoldOffUntil(rec servicespec.LastStopFileRecord, configPath string, now time.Time) (time.Time, bool) {
	return laststop.StartHoldOffUntil(rec, configPath, now)
}

// engineTerminal is engine.Terminal on the CLI shell and the machine's
// files (engineos).
type engineTerminal struct{ engineos.OS }

func (engineTerminal) TerminalText(s string) string { return cli.TerminalText(s) }

func (engineTerminal) InfoOwnerUID(fi os.FileInfo) (int, bool) { return cli.InfoOwnerUID(fi) }

// WriteFileAtomic writes last-stop.json, the one record of why the
// supervisor gave up, which it writes just before it exits: the directory
// is synced so the record survives a crash.
func (engineTerminal) WriteFileAtomic(path string, data []byte) error {
	return atomicfile.Write(path, data, atomicfile.Options{Mode: config.FileMode, SyncDir: true})
}

func (engineTerminal) HeldAtEveryLook(held func() bool, sleep func(time.Duration)) bool {
	return cli.HeldAtEveryLook(held, sleep)
}

func (engineTerminal) LoadEngineConfigAs(euid int, path string) (config.Config, error) {
	return cli.LoadEngineConfigAs(shell{}, euid, path)
}
