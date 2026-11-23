package engine

import (
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// engineCommand is the command that runs the engine.
const engineCommand = "engine"

// DialogEngineArgs is the command the first install's unit runs.
func DialogEngineArgs(goos, bin string) []string {
	return []string{bin, engineCommand, "--config", config.DefaultPath(goos), "--supervise"}
}

// DarwinEngineLog is the engine service's log on macOS (the unit's
// StandardErrorPath).
const DarwinEngineLog = "/Library/Logs/Basalt/engine.log"

// LogHint says where the engine service writes its log on goos.
func LogHint(goos string) string {
	if goos == "darwin" {
		return DarwinEngineLog
	}
	return "journalctl -u " + servicespec.SystemdUnitName
}

// CrashLoops: the service manager started the engine again after it
// exited with an error, so waiting longer for its page shows nothing new.
func CrashLoops(runs, lastExit int) bool {
	return runs >= 2 && lastExit > 0
}
