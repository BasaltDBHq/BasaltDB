package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/config"
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
type crashHost struct{}

func (crashHost) NewRecorder(command string) (engine.Recorder, []string) { return newRecorder(command) }

// engineTerminal is engine.Terminal on the CLI shell.
type engineTerminal struct{}

func (engineTerminal) TerminalText(s string) string { return cli.TerminalText(s) }

func (engineTerminal) InfoOwnerUID(fi os.FileInfo) (int, bool) { return cli.InfoOwnerUID(fi) }

// crashRecorder is engine.Recorder on the crash recorder rec.
type crashRecorder struct{ rec app.CrashRecorder }

func (r crashRecorder) Save(dir string, shared bool, in app.CrashInput) (string, error) {
	r.rec.Dir, r.rec.Shared = dir, shared
	rep, err := r.rec.Save(in)
	return rep.ID, err
}

// newRecorder is the recorder for this process and the directories to try,
// in order: the engine's state directory for the engine, the person's config
// directory for every other command.
func newRecorder(command string) (engine.Recorder, []string) {
	rec := app.CrashRecorder{Version: buildinfo.Version, Scrub: app.CrashOSScrubber(), Now: time.Now}
	user, state := engine.UserCrashDir(osHost{}), filepath.Join(config.DefaultStateDir(cli.GoosNow()), app.CrashDirName)
	dirs := []string{user, state}
	if command == "engine" {
		dirs = []string{state, user}
	}
	return crashRecorder{rec}, cli.NonEmpty(dirs)
}
