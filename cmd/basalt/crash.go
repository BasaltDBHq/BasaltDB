package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// Crash reports (CONTRACT.md, Crash reports): a panic in a command is
// saved as a scrubbed report on this machine, and nothing is sent anywhere.
// The agent's status tool names the newest one and the link to file it.

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
		reportPanic(std.Err, commandName(args), v, debug.Stack())
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

// reportPanic saves the report and prints the one line that names it. When
// nothing can be saved it says so, still without the panic's text, which can
// hold what the command was working on.
func reportPanic(w io.Writer, command string, v any, stack []byte) {
	rec, dirs := newRecorder(command)
	var lastErr error
	for _, dir := range dirs {
		rec.Dir = dir
		rec.Shared = command == "engine" && dir == dirs[0]
		rep, err := rec.Save(app.CrashInput{Command: command, Kind: app.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		if err == nil {
			fmt.Fprintf(w, "basalt: crashed; report %s was saved in %s: the agent's status tool names it, with the link to file it on GitHub\n", rep.ID, cli.TerminalText(dir))
			return
		}
		lastErr = err
	}
	fmt.Fprintf(w, "basalt: crashed, and the crash report could not be saved (%s)\n", cli.TerminalText(lastErr.Error()))
}

// newRecorder is the recorder for this process and the directories to try,
// in order: the engine's state directory for the engine, the person's config
// directory for every other command.
func newRecorder(command string) (app.CrashRecorder, []string) {
	rec := app.CrashRecorder{Version: buildinfo.Version, Scrub: app.CrashOSScrubber(), Now: time.Now}
	user, state := userCrashDir(), filepath.Join(config.DefaultStateDir(cli.GoosNow()), app.CrashDirName)
	dirs := []string{user, state}
	if command == "engine" {
		dirs = []string{state, user}
	}
	return rec, cli.NonEmpty(dirs)
}

func userCrashDir() string {
	base, err := osHost{}.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, perUserDirName, app.CrashDirName)
}
