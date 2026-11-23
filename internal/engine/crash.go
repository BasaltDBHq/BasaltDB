package engine

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Crash reports (CONTRACT.md, Crash reports): a panic in a command is
// saved as a scrubbed report on this machine, and nothing is sent anywhere.
// The agent's status tool names the newest one and the link to file it.

// Recorder saves this process's crash reports.
type Recorder interface {
	// Save saves in as a report in dir, readable by the engine's group when
	// shared, and returns the report's id.
	Save(dir string, shared bool, in servicespec.CrashInput) (id string, err error)
}

// Host is what the engine's use cases reach outside themselves.
type Host interface {
	// NewRecorder is the recorder for this process and the directories to
	// try, in order, for command.
	NewRecorder(command string) (Recorder, []string)
}

// Terminal is the CLI shell's text for a terminal.
type Terminal interface {
	// TerminalText is s safe to print on a terminal.
	TerminalText(s string) string
}

// osHost is the machine's per-user config directory.
type osHost interface {
	UserConfigDir() (string, error)
}

// ReportPanic saves the report and prints the one line that names it. When
// nothing can be saved it says so, still without the panic's text, which can
// hold what the command was working on.
func ReportPanic(h Host, t Terminal, w io.Writer, command string, v any, stack []byte) {
	rec, dirs := h.NewRecorder(command)
	var lastErr error
	for _, dir := range dirs {
		shared := command == "engine" && dir == dirs[0]
		id, err := rec.Save(dir, shared, servicespec.CrashInput{Command: command, Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		if err == nil {
			fmt.Fprintf(w, "basalt: crashed; report %s was saved in %s: the agent's status tool names it, with the link to file it on GitHub\n", id, t.TerminalText(dir))
			return
		}
		lastErr = err
	}
	fmt.Fprintf(w, "basalt: crashed, and the crash report could not be saved (%s)\n", t.TerminalText(lastErr.Error()))
}

// UserCrashDir is the person's crash directory on h, "" when h has no
// per-user config directory.
func UserCrashDir(h osHost) string {
	base, err := h.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, config.UserDirName, servicespec.CrashDirName)
}
