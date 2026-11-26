package app

import (
	"log/slog"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/lib/uniqueid"
)

// onPanic is the MCP servers' OnPanic, logging to log: a tool that panicked
// leaves a scrubbed crash report in the state directory (CONTRACT.md, Crash
// reports) and the call ends with INTERNAL. It logs the panic under a new
// error id, whether the report could be saved or not, and returns that id
// with the report's id ("" when the report could not be saved). The log line
// carries the tool and the ids, never the panic's value or stack: only the
// scrubbed report holds those.
func (env agentEnv) onPanic(log *slog.Logger) func(tool string, v any, stack []byte) (errorID, reportID string) {
	return func(tool string, v any, stack []byte) (string, string) {
		id := uniqueid.New()
		rec := crash.Recorder{
			Dir: filepath.Join(env.stateDir, servicespec.CrashDirName), Version: buildinfo.Version,
			Scrub: crash.OSScrubber(), Now: time.Now, Shared: true,
		}
		rep, err := rec.Save(servicespec.CrashInput{Command: tool, Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: v, Stack: stack})
		if err != nil {
			log.Error("tool panicked; no crash report saved", "tool", tool, "code", "INTERNAL", "error_id", id, "err", err)
			return id, ""
		}
		log.Error("tool panicked", "tool", tool, "code", "INTERNAL", "error_id", id, "report_id", rep.ID)
		return id, rep.ID
	}
}
