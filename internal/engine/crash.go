package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Crash reports (CONTRACT.md, Crash reports): a panic in a command is
// saved as a scrubbed report on this machine, and nothing is sent anywhere.
// The agent's status tool names the newest one and the link to file it.

// Recorder saves this process's crash reports.
type Recorder interface {
	// SaveIn saves in as a report in dir, readable by the engine's group
	// when shared, and returns the report's id.
	SaveIn(dir string, shared bool, in servicespec.CrashInput) (id string, err error)
}

// Host is what the engine's use cases reach outside themselves.
type Host interface {
	CrashDirHost
	// NewRecorder is the crash recorder for this process.
	NewRecorder() Recorder
	// LastStopHashEngineJSON is the hash of the engine config at path that
	// a give-up records.
	LastStopHashEngineJSON(path string) string
}

// Terminal is what the engine's use cases read from the CLI shell.
type Terminal interface {
	// TerminalText is s safe to print on a terminal.
	TerminalText(s string) string
	// InfoOwnerUID is the owner of the file fi describes; false where the
	// platform has no owners.
	InfoOwnerUID(fi os.FileInfo) (int, bool)
	// WriteFileAtomic writes data to path so a reader sees the old file or
	// the new one, never part of it.
	WriteFileAtomic(path string, data []byte) error
	// HeldAtEveryLook is true when held is true at every one of a few looks,
	// sleep apart.
	HeldAtEveryLook(held func() bool, sleep func(time.Duration)) bool
}

// CrashDirHost is the machine's per-user config directory.
type CrashDirHost interface {
	UserConfigDir() (string, error)
}

// ReportPanic saves the report and prints the one line that names it. When
// nothing can be saved it says so, still without the panic's text, which can
// hold what the command was working on.
func ReportPanic(h Host, t Terminal, w io.Writer, command string, v any, stack []byte) {
	rec, dirs := h.NewRecorder(), crashDirs(h, command)
	var lastErr error
	for _, dir := range dirs {
		shared := command == "engine" && dir == dirs[0]
		id, err := rec.SaveIn(dir, shared, servicespec.CrashInput{Command: command, Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
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
