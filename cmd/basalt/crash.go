package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// Crash reports (CONTRACT.md, Crash reports): a panic in a command is
// saved as a scrubbed report on this machine, and nothing is sent anywhere.
// The agent's status tool names the newest one and the link to file it.

// runGuarded runs the command line and turns a panic into a saved crash
// report, one line on stderr and exit code 1.
func runGuarded(ctx context.Context, args []string, std stdio) int {
	return guarded(args, std, func() int { return run(ctx, args, std) })
}

// guarded runs f, which runs the command line args.
func guarded(args []string, std stdio, f func() int) (code int) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		code = exitError
		reportPanic(std.err, commandName(args), v, debug.Stack())
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
		if cmd.name == args[0] {
			return cmd.name
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
		rep, err := rec.Save(crash.Input{Command: command, Kind: crash.KindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		if err == nil {
			fmt.Fprintf(w, "basalt: crashed; report %s was saved in %s: the agent's status tool names it, with the link to file it on GitHub\n", rep.ID, terminalText(dir))
			return
		}
		lastErr = err
	}
	fmt.Fprintf(w, "basalt: crashed, and the crash report could not be saved (%s)\n", terminalText(lastErr.Error()))
}

// newRecorder is the recorder for this process and the directories to try,
// in order: the engine's state directory for the engine, the person's config
// directory for every other command.
func newRecorder(command string) (crash.Recorder, []string) {
	rec := crash.Recorder{Version: buildinfo.Version, Scrub: crash.OSScrubber(), Now: time.Now}
	user, state := userCrashDir(), filepath.Join(config.DefaultStateDir(goosNow()), crash.DirName)
	dirs := []string{user, state}
	if command == "engine" {
		dirs = []string{state, user}
	}
	return rec, nonEmpty(dirs)
}

func userCrashDir() string {
	base, err := osHost{}.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, perUserDirName, crash.DirName)
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func goosNow() string { return runtime.GOOS }
