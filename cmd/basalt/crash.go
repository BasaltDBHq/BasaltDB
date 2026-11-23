package main

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// runGuarded runs the command line and turns a panic into a saved crash
// report, one line on stderr and exit code 1.
func runGuarded(ctx context.Context, args []string, std cli.Stdio) int {
	return guarded(args, std, func() int { return run(ctx, args, std) })
}

// guarded runs f, which runs the command line args.
func guarded(args []string, std cli.Stdio, f func() int) (code int) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		code = cli.ExitError
		engine.ReportPanic(crashHost{}, engineTerminal{}, std.Err, commandName(args), v, debug.Stack())
	}()
	return f()
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

// crashHost is the crash use case's engine.Host.
type crashHost struct{ osHost }

func (crashHost) NewRecorder() engine.Recorder { return newRecorder() }

// engineTerminal is engine.Terminal on the CLI shell.
type engineTerminal struct{}

func (engineTerminal) TerminalText(s string) string { return cli.TerminalText(s) }

func (engineTerminal) InfoOwnerUID(fi os.FileInfo) (int, bool) { return cli.InfoOwnerUID(fi) }

// newRecorder is the crash recorder for this process.
func newRecorder() engine.Recorder {
	return app.CrashRecorder{Version: buildinfo.Version, Scrub: app.CrashOSScrubber(), Now: time.Now}
}
