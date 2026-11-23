package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// runGuarded runs the command line and turns a panic into a saved crash
// report, one line on stderr and exit code 1.
func runGuarded(ctx context.Context, args []string, std cli.Stdio) int {
	return enginecli.Guarded(engineCLIHost{}, engineHost{}, engineTerminal{}, args, std, func() int { return run(ctx, args, std) })
}

// engineCLIHost is enginecli.Host for the command table, through app.
type engineCLIHost struct{}

func (engineCLIHost) CommandName(args []string) string { return commandName(args) }

func (engineCLIHost) Fail(w io.Writer, name string, err error) int { return fail(w, name, err) }

func (engineCLIHost) ChildStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error) {
	return childStarter(startedFrom, configPath, lockPath, stateDir, io, log)
}

func (engineCLIHost) RunServiceAt(ctx context.Context, args []string, io cli.Stdio, configPath string) int {
	return runServiceAt(ctx, args, io, configPath)
}

func (engineCLIHost) EngineLog(w io.Writer) *slog.Logger { return engineLog(w) }

func (engineCLIHost) EngineDown(name, configPath string, log *slog.Logger) (agent.EngineDown, error) {
	return engineDown(name, configPath, log)
}

func (engineCLIHost) EngineStarter(configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (func(context.Context) error, func() string) {
	return app.EngineStarter(engineHost{}, shim.DefaultStartWait, configPath, socket, cfg, euid, exe, log)
}

func (engineCLIHost) NewEngineDownServer(down agent.EngineDown) shim.Fallback {
	return app.NewEngineDownServer(down)
}

// commandName is the command a command line runs, for the report: only a
// name from the command list, never an argument.
func commandName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	for _, cmd := range commands() {
		if cmd.Name == args[0] {
			return cmd.Name
		}
	}
	return ""
}

// engineHost is engine.Host through app and the machine.
type engineHost struct{ osHost }

func (engineHost) NewRecorder() engine.Recorder { return newRecorder() }

func (engineHost) LastStopHashEngineJSON(path string) string { return app.LastStopHashEngineJSON(path) }

func (engineHost) LastStopStartHoldOffUntil(rec servicespec.LastStopFileRecord, configPath string, now time.Time) (time.Time, bool) {
	return app.LastStopStartHoldOffUntil(rec, configPath, now)
}

// engineTerminal is engine.Terminal on the CLI shell.
type engineTerminal struct{}

func (engineTerminal) TerminalText(s string) string { return cli.TerminalText(s) }

func (engineTerminal) InfoOwnerUID(fi os.FileInfo) (int, bool) { return cli.InfoOwnerUID(fi) }

func (engineTerminal) WriteFileAtomic(path string, data []byte) error {
	return cli.WriteFileAtomic(path, data)
}

func (engineTerminal) HeldAtEveryLook(held func() bool, sleep func(time.Duration)) bool {
	return cli.HeldAtEveryLook(held, sleep)
}

func (engineTerminal) LoadEngineConfigAs(euid int, path string) (config.Config, error) {
	return cli.LoadEngineConfigAs(appShell{}, euid, path)
}

// newRecorder is the crash recorder for this process.
func newRecorder() engine.Recorder {
	return app.CrashRecorder{Version: buildinfo.Version, Scrub: app.CrashOSScrubber(), Now: time.Now}
}
