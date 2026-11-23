package app

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// onPanic is the MCP servers' OnPanic: a tool that panicked leaves a
// scrubbed crash report in the state directory (CONTRACT.md, Crash reports)
// and the call ends with INTERNAL. It returns the report's id, or "" when
// the report could not be saved.
func (env agentEnv) onPanic(tool string, v any, stack []byte) string {
	rec := crash.Recorder{
		Dir: filepath.Join(env.stateDir, servicespec.CrashDirName), Version: buildinfo.Version,
		Scrub: crash.OSScrubber(), Now: time.Now, Shared: true,
	}
	rep, err := rec.Save(servicespec.CrashInput{Command: tool, Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
	if err != nil {
		return ""
	}
	return rep.ID
}

// crashDirs are the directories status.crash reads, so a panic of the engine process itself (saved
// under the default state directory or the person's config directory) shows
// as well as a tool call's (under stateDir).
func crashDirs(stateDir string) []string {
	dirs := []string{filepath.Join(stateDir, servicespec.CrashDirName)}
	if base, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(base, "basalt", servicespec.CrashDirName), filepath.Join(base, "basalt", "state", servicespec.CrashDirName))
	}
	dirs = append(dirs, filepath.Join(config.DefaultStateDir(runtime.GOOS), servicespec.CrashDirName))
	return slices.Compact(dirs)
}
