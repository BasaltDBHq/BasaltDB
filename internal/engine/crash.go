package engine

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Crash reports (CONTRACT.md, Crash reports): a panic in a command is
// saved as a scrubbed report on this machine, and nothing is sent anywhere.
// The agent's status tool names the newest one and the link to file it.

// ReportPanic saves the report and prints the one line that names it. When
// nothing can be saved it says so, still without the panic's text, which can
// hold what the command was working on.
func ReportPanic(h Host, t Terminal, w io.Writer, command string, v any, stack []byte) {
	rec, dirs := h.NewRecorder(), crashDirs(h, command)
	var lastErr error
	for _, dir := range dirs {
		shared := command == engineCommand && dir == dirs[0]
		id, err := rec.SaveIn(dir, shared, servicespec.CrashInput{Command: command, Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		// A report written whose older ones could not be deleted is saved.
		if err == nil || errors.Is(err, servicespec.ErrCrashNotPruned) {
			fmt.Fprintf(w, "basalt: crashed; report %s was saved in %s: the agent's status tool names it, with the link to file it on GitHub\n", id, t.TerminalText(dir))
			return
		}
		lastErr = err
	}
	fmt.Fprintf(w, "basalt: crashed, and the crash report could not be saved (%s)\n", t.TerminalText(lastErr.Error()))
}

// UserCrashDir is the person's crash directory on h, "" when h has no
// per-user config directory.
func UserCrashDir(h CrashDirHost) string {
	base, err := h.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, config.UserDirName, servicespec.CrashDirName)
}

// crashDirs are the directories to try, in order: the engine's state
// directory for the engine, the person's config directory for every other
// command; one that is unknown is left out.
func crashDirs(h CrashDirHost, command string) []string {
	user, state := UserCrashDir(h), filepath.Join(config.DefaultStateDir(runtime.GOOS), servicespec.CrashDirName)
	dirs := []string{user, state}
	if command == "engine" {
		dirs = []string{state, user}
	}
	var out []string
	for _, d := range dirs {
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
