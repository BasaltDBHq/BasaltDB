package main

import (
	"context"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// runGuarded runs the command line and turns a panic into a saved crash
// report, one line on stderr and exit code 1.
func runGuarded(ctx context.Context, args []string, std cli.Stdio) int {
	return enginecli.Guarded(engineCLIHost{}, engineHost{}, engineTerminal{}, args, std, func() int { return run(ctx, args, std) })
}

// engineCLIHost is enginecli.Host for the command table.
type engineCLIHost struct{}

func (engineCLIHost) CommandName(args []string) string { return commandName(args) }

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
