// Package enginecli is the engine's side of the CLI: the controllers of
// basalt engine, basalt mcp and basalt service, and the crash guard every
// command runs under.
package enginecli

import (
	"context"
	"io"
	"log/slog"
	"runtime/debug"

	"github.com/basaltdbhq/basaltdb/internal/status/in/statusmcp"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
)

// Host is what the engine's CLI controllers reach outside themselves.
type Host interface {
	// CommandName is the command a command line runs, for a crash report:
	// only a name from the command list, never an argument.
	CommandName(args []string) string
	// Fail prints err for command name and returns the error exit code.
	Fail(w io.Writer, name string, err error) int
	// EngineLog is the log basalt mcp writes to w.
	EngineLog(w io.Writer) *slog.Logger
	// EngineDown is the engine-down service for the agent name of the
	// engine whose config is at configPath.
	EngineDown(name, configPath string, log *slog.Logger) (statusmcp.EngineDown, error)
	// EngineStarter starts the engine for socket when it does not answer;
	// failure says why the last start failed.
	EngineStarter(configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string)
	// NewEngineDownServer is down's tools, served as the agent's MCP server.
	NewEngineDownServer(down statusmcp.EngineDown) shim.Fallback
	// ChildStarter runs the engine as startedFrom engine --config ...
	// --started-by ... with io's output, for basalt engine --supervise.
	ChildStarter(startedFrom, configPath, lockPath, stateDir string, io cli.Stdio, log *slog.Logger) func(context.Context, string) (func() error, error)
	// RunServiceAt is basalt service on the engine config at configPath.
	RunServiceAt(ctx context.Context, args []string, io cli.Stdio, configPath string) int
	// SocketAgents are the agents with a socket in dir.
	SocketAgents(dir string) []string
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
