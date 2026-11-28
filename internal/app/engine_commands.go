package app

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/in/enginecli"
	"github.com/basaltdbhq/basaltdb/internal/lib/logredact"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// runEngine runs the engine service; the launchd or systemd unit starts it.
func runEngine(ctx context.Context, args []string, io cli.Stdio) int {
	return runEngineOn(ctx, args, io, osHost{})
}

// runEngineOn is runEngine with the host that tells root and the config dir.
func runEngineOn(ctx context.Context, args []string, io cli.Stdio, h cli.Machine) int {
	fs := cli.NewFlagSet("engine")
	fs.SetOutput(io.Err)
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	supervised := fs.Bool("supervise", false, "run the engine as a child and restart it when it crashes")
	startedBy := fs.String("started-by", startedByHand, "why this engine started: hand, mcp, crash or service (set by basalt mcp, --supervise and the service unit)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return cli.ExitUsage
	}
	if !slices.Contains([]string{startedByHand, engine.StartedByMCP, engine.StartedByCrash, engine.StartedByService}, *startedBy) {
		_, _ = fmt.Fprintf(io.Err, "basalt engine: --started-by is hand, mcp, crash or service, not %q\n", *startedBy)
		return cli.ExitUsage
	}
	*configPath = cli.ConfigOrFallback(h, fs, *configPath)
	// Started as root, the hardened read: the config's
	// directory may belong to another user, who could plant a link there.
	if *supervised {
		return enginecli.RunSupervise(ctx, engine.EnginePath(*configPath), *startedBy, io, h, engineCLIHost{}, engineHost{}, engineTerminal{}, binaryWatch{})
	}
	// A supervised child on macOS stops when its supervisor dies.
	watchSupervisedParent(ctx)
	log := logredact.NewTextLogger(io.Err)
	// handed is the setup page's listener of an engine that waited for its
	// config: the first run serves its own pages on it.
	var handed net.Listener
	if engine.WaitsForConfig(engineTerminal{}, h.Euid(), engine.EnginePath(*configPath)) {
		ln, err := WaitForConfig(ctx, WaitOptions{Addr: setup.PageAddr, Origin: setup.PageOrigin, ConfigPath: *configPath, Log: log})
		if err != nil {
			if ctx.Err() != nil {
				return cli.ExitOK
			}
			return fail(io.Err, "engine", err)
		}
		handed = ln
	}
	cfg, err := cli.LoadEngineConfigAs(shell{}, h.Euid(), *configPath)
	if err != nil {
		return fail(io.Err, "engine", err)
	}
	// One store for the whole process, outside run: a config reload (the
	// certificate fix, a reinstall) calls run again and builds a new setup
	// service, and basalt init's wait must still see what the old one marked.
	marks := setup.NewMarks()
	run := func(ctx context.Context, r engine.Restart) error {
		o := restartOptions{Restart: r, Removal: &selfRemoval{}, SetupMarks: marks}
		o.StartedBy = *startedBy
		o.PagesListener, handed = handed, nil
		err := runWith(ctx, cfg, engine.EnginePath(*configPath), log, o)
		if rm := o.Removal.taken(); rm != nil {
			// BasaltDB was removed from the agent's database on the connect
			// page: everything runWith opened is closed, so the engine
			// deletes its folders, reports and exits cleanly (a supervisor
			// then stops too). When engine.json changed since the
			// confirmation (another agent, a newer link), nothing is deleted
			// and the engine serves its config again, as for a reload.
			if !finishSelfRemoval(ctx, engine.EnginePath(*configPath), rm, log) {
				return engine.ErrReload
			}
			return nil
		}
		return err
	}
	// A reload (a connect-only agent's setup changed) serves the config as
	// it is now.
	reload := func() error {
		next, err := cli.LoadEngineConfigAs(shell{}, h.Euid(), *configPath)
		if err != nil {
			return err
		}
		cfg = next
		return nil
	}
	if err := engine.ServeRestarting(ctx, run, osRestart(log), reload, log); err != nil {
		return fail(io.Err, "engine", err)
	}
	return cli.ExitOK
}

// runMCP is the agent's MCP server: a relay from stdio to the agent's engine
// socket. It never reads a credential or reaches a database. While the
// socket does not answer it serves status and the tool list itself and
// answers every other call UNAVAILABLE ENGINE_UNREACHABLE (CONTRACT.md, Next
// steps, Startup failures).
func runMCP(ctx context.Context, args []string, io cli.Stdio) int {
	return enginecli.RunMCPOn(ctx, args, io, osHost{}, engineCLIHost{})
}

// runService is basalt service for the command table.
func runService(ctx context.Context, args []string, io cli.Stdio) int {
	return enginecli.RunService(ctx, args, io, engineCLIHost{})
}
