package enginecli

import (
	"cmp"
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// RunMCPOn is basalt mcp with the host that tells root and the config dir, and
// m, what it reaches outside the CLI.
func RunMCPOn(ctx context.Context, args []string, io cli.Stdio, h cli.Machine, m Host) int {
	return RunMCPAt(ctx, args, io, h, m, config.DefaultPath(runtime.GOOS))
}

// RunMCPAt is RunMCPOn with the system path of engine.json (tests give
// their own). The config is found by itself ([Config discovery]); the socket
// directory and, when the engine serves one agent, the agent come from it.
func RunMCPAt(ctx context.Context, args []string, io cli.Stdio, h cli.Machine, m Host, system string) int {
	fs := cli.NewFlagSet("mcp")
	fs.SetOutput(io.Err)
	name := fs.String("agent", "", "agent name (needed only when the engine serves more than one agent)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return cli.ExitUsage
	}
	cfgPath, err := cli.DiscoverConfig(h, system)
	if err != nil {
		return m.Fail(io.Err, "mcp", err)
	}
	socketDir := config.DefaultSocketDir(runtime.GOOS)
	var names []string
	if cfg, err := config.Load(cfgPath); err == nil {
		socketDir = cmp.Or(cfg.SocketDir, socketDir)
		for _, a := range cfg.Agents {
			names = append(names, a.Name)
		}
	} else {
		// A service engine's config is the engine's own: the person can
		// list its socket directory, not read the config.
		names = engine.SocketAgents(socketDir)
	}
	if *name == "" {
		if len(names) != 1 {
			m.Fail(io.Err, "mcp", fmt.Errorf("%w: --agent NAME is needed: the engine serves %s", cli.ErrUsage, cmp.Or(strings.Join(names, ", "), "no agent")))
			return cli.ExitUsage
		}
		*name = names[0]
	}
	if !config.ValidAgentName(*name) {
		fs.Usage()
		return cli.ExitUsage
	}
	path := config.SocketPath(socketDir, *name)
	log := m.EngineLog(io.Err)
	down, err := m.EngineDown(engine.ShimAgent(*name, path), engine.EnginePath(cfgPath), log)
	if err != nil {
		return m.Fail(io.Err, "mcp", err)
	}
	// Links to the engine's own local pages open in the browser on a
	// person-operated engine; the engine says which in its hello answer.
	// A plugin the agent asks for (request_plugin) is uploaded over a
	// second connection to the agent's own socket.
	opts := shim.Options{Open: h.OpenURL, UploadPlugin: shim.NewPluginUploader(path), UploadAllowed: plugin.UploadAllowed}
	if exe, err := cli.ShimExecutable(); err == nil {
		var failure func() string
		opts.Start, failure = m.EngineStarter(engine.EnginePath(cfgPath), path, down.Config, h.Euid(), exe, log)
		down.StartFailure = failure
	}
	if err := shim.ServeWith(ctx, path, m.NewEngineDownServer(down), io.In, io.Out, opts); err != nil {
		return m.Fail(io.Err, "mcp", err)
	}
	return cli.ExitOK
}
