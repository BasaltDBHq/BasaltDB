package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pluginledger"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginpath"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// The plugin host (internal/plugin) holds
// the plugin feature: verifying, running and feeding plugins, and their
// approvals. This file builds what it reaches the outside world with and
// hands it over: the path rule, the guard's plugin ledger, the transports,
// the OS units and the MCP methods of an upload.

func init() {
	// The path rule is the one port the host's free functions read, so it is
	// installed once for the process; every other port travels in the
	// options.
	plugin.UsePathRules(pluginpath.Rules{})
}

// pluginPorts are the adapters the plugin feature is built on.
var pluginPorts = plugin.Ports{
	Guard:            pluginledger.Ledger{},
	InGroup:          osservice.InGroup,
	SystemdOverrides: osservice.SystemdOverridesOnMachine,
	NewUnitHost: func(host servicespec.PluginHost) plugin.UnitHost {
		return osservice.NewPluginUnitHost(host)
	},
}

// pluginRunsDirName is the directory under the engine's state directory
// that holds its plugin run records.
const pluginRunsDirName = "plugin-runs"

// pluginRuns is where a same-user engine records the local plugin processes
// it starts, after reaping what an earlier run of it left: processes still
// running and their socket directories (CONTRACT.md, Plugins, Transports).
// It runs under the engine lock, before any plugin starts, whether or not a
// plugin is enabled now. A service engine runs its approved engine-kept
// local entries itself, so it records and reaps them as a same-user engine
// does; an engine run as root starts no local plugin: nil.
func pluginRuns(cfg config.Config, stateDir string, euid int, log *slog.Logger) *child.Runs {
	_ = cfg
	if euid == 0 || stateDir == "" {
		return nil
	}
	dir := filepath.Join(stateDir, pluginRunsDirName)
	child.Reap(dir, log)
	return &child.Runs{Dir: dir}
}

var pluginDebugWriter = plugin.DebugWriter

// pluginOptions are how the engine reaches its plugins.
type pluginOptions struct {
	// Stderr receives local plugins' stderr (basalt engine --plugin-debug);
	// nil discards it.
	Stderr io.Writer
	euid   int
	// runs records each local plugin process the engine starts (pluginRuns).
	runs     *child.Runs
	stateDir string
	// kept is a service engine's own entries; nil in same-user mode.
	kept *plugin.Store
}

func (o pluginOptions) engine() plugin.Options {
	return plugin.NewOptions(o.Stderr, o.euid, o.stateDir, o.kept, dial.Dialer{Runs: o.runs}, pluginPorts)
}

func newEnginePlugins(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *plugin.Plugins {
	return plugin.New(cfg, configPath, o.engine(), log)
}

func newEnginePluginsFor(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *plugin.Plugins {
	return plugin.NewFor(cfg, configPath, o.engine(), log)
}

var openKeptStore = plugin.OpenKeptStore

// pluginLedger is one agent's ledger as the plugin event writer reaches it:
// the agent's own connection, and the engine's admission of the agent (nil
// admits it).
type pluginLedger struct {
	db    plugin.Querier
	admit func(context.Context) error
}

func pluginLedgers(m map[string]pluginLedger) map[string]plugin.AgentLedger {
	out := make(map[string]plugin.AgentLedger, len(m))
	for name, l := range m {
		out[name] = plugin.NewAgentLedger(l.db, l.admit, pluginPorts)
	}
	return out
}

func recordPluginEvents(ctx context.Context, cfg config.Config, configPath string, ep *plugin.Plugins, ledgers map[string]pluginLedger, log *slog.Logger) {
	plugin.RecordEvents(ctx, cfg, configPath, ep, pluginLedgers(ledgers), log)
}

// pluginAdmit is svc's admission for plugin records: plugin.ErrNotAdmitted
// when the agent is served status only (no guard, an outdated one, a pending
// setup), the probe's error when its database does not answer.
func pluginAdmit(svc *agent.Service) func(context.Context) error {
	return func(ctx context.Context) error {
		err := svc.Admit(ctx)
		var te *toolresult.ToolError
		var se *guidance.SetupError
		if errors.As(err, &te) || errors.As(err, &se) {
			return fmt.Errorf("%w: %w", plugin.ErrNotAdmitted, err)
		}
		return err
	}
}

// keptAgent is an agent as the plugin methods reach it.
type keptAgent struct {
	db       plugin.Querier
	host     string
	port     uint16
	database string
	role     string
}

func openKeptPlugins(cfg config.Config, configPath string, store *plugin.Store, ep *plugin.Plugins, agents map[string]keptAgent, log *slog.Logger) *plugin.KeptPlugins {
	kept := make(map[string]plugin.KeptAgent, len(agents))
	for name, a := range agents {
		kept[name] = plugin.NewKeptAgent(a.db, a.host, a.port, a.database, a.role)
	}
	return plugin.OpenKeptPlugins(cfg, configPath, store, ep, kept, log, pluginPorts)
}

// pluginRequests serve the agents' request_plugin calls with the
// engine-kept entries, and the upload methods of an agent's own socket.
type pluginRequests struct {
	*plugin.Requests
}

func newPluginRequests(uids map[string]uint32, admitted []uint32) *pluginRequests {
	return &pluginRequests{Requests: plugin.NewRequests(uids, admitted)}
}

// uploadMethods are the methods basalt mcp calls on a second connection to
// caller's own socket to upload a plugin's files (CONTRACT.md, MCP tools,
// request_plugin).
func (p *pluginRequests) uploadMethods(caller string, served func() error) map[string]mcpserver.MethodFunc {
	if p == nil {
		return nil
	}
	return map[string]mcpserver.MethodFunc{
		mcpserver.MethodPluginUploadBegin: func(ctx context.Context, _ json.RawMessage) (any, error) {
			out, err := p.UploadBegin(ctx, caller, served)
			if err != nil {
				return nil, uploadError(err)
			}
			return out, nil
		},
		mcpserver.MethodPluginUploadPart: func(ctx context.Context, raw json.RawMessage) (any, error) {
			out, err := p.UploadPart(ctx, caller, served, raw)
			if err != nil {
				return nil, uploadError(err)
			}
			return out, nil
		},
	}
}

// uploadError is the upload methods' answer for err.
func uploadError(err error) *toolresult.ToolError {
	var te *toolresult.ToolError
	var r *plugin.PluginRefusedError
	var ae *guidance.ArgumentError
	switch {
	case errors.As(err, &te):
		return te
	case errors.As(err, &r):
		return &toolresult.ToolError{Code: "PLUGIN_REFUSED", Reason: r.Reason, Message: r.Message}
	case errors.As(err, &ae):
		return &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: ae.Message}
	case errors.Is(err, plugin.ErrPluginNotFound):
		return &toolresult.ToolError{Code: guidance.CodeNotFound, Message: "the upload is unknown, expired or used"}
	}
	return &toolresult.ToolError{Code: guidance.CodeInternal, Message: "the engine could not take the plugin's files"}
}
