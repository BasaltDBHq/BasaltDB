// Package enginecli is the engine's side of the CLI: the controllers of
// basalt engine, basalt mcp and basalt service, and the crash guard every
// command runs under.
package enginecli

import (
	"runtime/debug"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// Host is what the engine's CLI controllers reach outside themselves.
type Host interface {
	// CommandName is the command a command line runs, for a crash report:
	// only a name from the command list, never an argument.
	CommandName(args []string) string
}

// Guarded runs f, which runs the command line args, and turns a panic into
// a saved crash report, one line on stderr and exit code 1.
func Guarded(h Host, eh engine.Host, t engine.Terminal, args []string, std cli.Stdio, f func() int) (code int) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		code = cli.ExitError
		engine.ReportPanic(eh, t, std.Err, h.CommandName(args), v, debug.Stack())
	}()
	return f()
}
