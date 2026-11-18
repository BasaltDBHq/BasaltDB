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
// The person reads it with basalt crash show and files it with basalt crash
// report, which only builds a GitHub link.

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
		rep, err := rec.Save(crash.Input{Command: command, Kind: crash.KindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		if err == nil {
			fmt.Fprintf(w, "basalt: crashed; a report was saved: see what it holds with `basalt crash show %s`, file it on GitHub with `basalt crash report %s`\n", rep.ID, rep.ID)
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

// crashDirs are the directories basalt crash reads: the person's, and the
// engine's state directory when the person can read it.
func (c *cliIO) crashDirs() []string {
	var dirs []string
	if base, err := c.host.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(base, perUserDirName, crash.DirName))
	}
	return append(dirs, filepath.Join(config.DefaultStateDir(c.goos), crash.DirName))
}

const crashUsage = "basalt crash list | show <id> | report <id>"

func runCrash(c *cliIO, args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("%w: %s", errUsage, crashUsage))
	}
	switch args[0] {
	case "list":
		return crashList(c, args[1:])
	case "show":
		return crashShow(c, args[1:])
	case "report":
		return crashReport(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown crash command %q (list, show, report)", errUsage, args[0]))
}

func crashList(c *cliIO, args []string) int {
	if err := parse(c.flags("crash list"), args); err != nil {
		return c.fail(err)
	}
	reports := crash.List(c.crashDirs()...)
	if len(reports) == 0 {
		fmt.Fprintln(c.stdout, "No crash reports are saved.")
		return exitOK
	}
	for _, r := range reports {
		fmt.Fprintf(c.stdout, "%s  %s  %s  %s\n", r.ID, r.Time.Format(time.RFC3339), r.Version, r.Command)
	}
	return exitOK
}

// crashID parses the one id argument of show and report.
func crashID(c *cliIO, name string, args []string) (crash.Report, error) {
	fs := c.flags("crash " + name)
	if err := fs.Parse(args); err != nil {
		return crash.Report{}, fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() != 1 {
		return crash.Report{}, fmt.Errorf("%w: basalt crash %s <id>", errUsage, name)
	}
	rep, err := crash.Find(fs.Arg(0), c.crashDirs()...)
	if err != nil {
		return rep, fmt.Errorf("crash %s: %w", name, err)
	}
	return rep, nil
}

// crashShow prints exactly the report: what crash report puts in the issue.
func crashShow(c *cliIO, args []string) int {
	rep, err := crashID(c, "show", args)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprint(c.stdout, rep.Show())
	return exitOK
}

// crashReport builds the pre-filled issue link. It opens it only for a person
// at a terminal; under an agent it opens and prints nothing but the command
// for the person.
func crashReport(c *cliIO, args []string) int {
	rep, err := crashID(c, "report", args)
	if err != nil {
		return c.fail(err)
	}
	if marker := c.agentMarker(); marker != "" {
		fmt.Fprintf(c.stdout, "basalt crash report opens nothing under an agent (%s is set). "+
			"Tell the person to run `basalt crash report %s` in a terminal of their own: it opens a GitHub issue they read and submit themselves.\n",
			marker, rep.ID)
		return exitOK
	}
	link, trimmed := rep.IssueURL()
	if trimmed {
		fmt.Fprintln(c.stderr, "basalt: the stack was cut to fit the link; `basalt crash show "+rep.ID+"` has all of it")
	}
	if c.interactive {
		if err := c.host.OpenURL(c.ctx, link); err == nil {
			fmt.Fprintln(c.stdout, "Opened a new GitHub issue in your browser. Read it, and submit it only if you want to.")
			return exitOK
		}
		fmt.Fprintln(c.stderr, "basalt: could not open a browser; the link is below")
	}
	fmt.Fprintln(c.stdout, "Open this link to file the crash on GitHub. Read it, and submit it only if you want to:")
	fmt.Fprintln(c.stdout, link)
	return exitOK
}

// goosNow is the platform basalt runs on.
func goosNow() string { return runtime.GOOS }
