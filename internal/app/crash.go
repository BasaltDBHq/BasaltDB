package app

import (
	"path/filepath"
	"time"

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
