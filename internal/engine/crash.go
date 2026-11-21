package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// onPanic is the MCP servers' OnPanic: a tool that panicked leaves a
// scrubbed crash report in the state directory (CONTRACT.md, Crash reports)
// and the call ends with INTERNAL. It returns the report's id, or "" when
// the report could not be saved.
func (env agentEnv) onPanic(tool string, v any, stack []byte) string {
	rec := crash.Recorder{
		Dir: filepath.Join(env.stateDir, crash.DirName), Version: buildinfo.Version,
		Scrub: crash.OSScrubber(), Now: time.Now, Shared: true,
	}
	rep, err := rec.Save(crash.Input{Command: tool, Kind: crash.KindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
	if err != nil {
		return ""
	}
	return rep.ID
}

// crashDirs are the directories status.crash reads: the same three
// basalt crash list read, so a panic of the engine process itself (saved
// under the default state directory or the person's config directory) shows
// as well as a tool call's (under stateDir).
func crashDirs(stateDir string) []string {
	dirs := []string{filepath.Join(stateDir, crash.DirName)}
	if base, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(base, "basalt", crash.DirName), filepath.Join(base, "basalt", "state", crash.DirName))
	}
	dirs = append(dirs, filepath.Join(config.DefaultStateDir(runtime.GOOS), crash.DirName))
	return slices.Compact(dirs)
}
