package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/child"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
)

// pluginOptions are how the engine reaches its plugins.
type pluginOptions struct {
	// Stderr receives local plugins' stderr (basalt engine --plugin-debug);
	// nil discards it. Never the engine's log.
	Stderr io.Writer
	// SocketBase is where socket plugins' socket directories are made; ""
	// is the OS temporary directory (dial.Options.SocketBase).
	SocketBase string
	// runs records each local plugin process the engine starts in
	// same-user mode (pluginRuns), so its next start reaps one a crash left
	// running; nil records nothing.
	runs *child.Runs
	// goos and euid default to the running engine's.
	goos string
	euid int
	// clock is the supervisor's; plugin.RealClock() when nil.
	clock plugin.Clock
	// units finds a service engine's plugin units; the machine's when nil.
	units *unitSource
}

// Why an entry is not started though it verified.
const (
	whyLocalAsRoot = "the engine runs as root, and a local plugin is never started with root's privileges"
	whyBadEntry    = "its entry in engine.json breaks a rule (see the engine's log)"
)

// enginePlugins are the plugin entries of a running engine (CONTRACT.md,
// Plugins): the enabled ones, verified at start and before every restart,
// run by a supervisor. It is the agents' status source for PLUGIN_UNAVAILABLE
// and PLUGIN_NOT_TRUSTED. A plugin that fails never stops the engine.
type enginePlugins struct {
	host *plugin.Host
	sup  *plugin.Supervisor
	log  *slog.Logger
	o    pluginOptions
	// configured are the enabled entries that list an agent, in config
	// order; entries are the ones the supervisor runs.
	configured []config.Plugin
	entries    []plugin.Entry

	mode  plugin.Mode
	root  string
	trust plugin.TrustStore

	mu sync.Mutex
	// first is each entry's copy verified at start, used by its first
	// start only, so a start does not hash every file twice.
	first map[plugin.EntryKey]plugin.Verified
	// notTrusted is why an entry failed verification, at start or before
	// its last restart; cleared when a later verification passes.
	notTrusted map[plugin.EntryKey]error
	// refused is why an entry that verified is not started.
	refused map[plugin.EntryKey]string
	// approval are the entries that require a plugin approval
	// (config.Config.PluginRequiresApproval). Such an entry is verified with
	// plugin.RequireApproval and starts with no agent: withhold grants it
	// each agent whose approval matched, and no other.
	approval map[plugin.EntryKey]bool
	// unrecorded are the agents each entry is withheld from, and why: its
	// ledger record could not be written, or, for an entry that requires
	// approval, its approval is missing or does not match (withhold).
	unrecorded map[plugin.EntryKey]map[string]withheldWhy
	// dialWhy is why a service entry's last connection failed, when the
	// cause is one status should name (nothing listens, the socket
	// directory changed).
	dialWhy map[plugin.EntryKey]string

	// In service mode: the units the engine expects (unitHost, or why it
	// cannot tell) and each reachable local entry's socket and OS user.
	unitHost    service.PluginHost
	unitHostErr error
	targets     map[plugin.EntryKey]serviceTarget
	// allKeys are every configured entry's, enabled or not.
	allKeys []plugin.EntryKey

	// rootErr is why no copy can be verified: the plugin root or the trust
	// store cannot be read.
	rootErr error
	// configProblem is why engine.json, changed while the engine runs,
	// cannot be read; "" when it can (pluginWatch).
	configProblem string
	// startChecks is each entry's check at start. Immutable once built.
	startChecks map[plugin.EntryKey]entryCheck
}

// newEnginePlugins verifies the enabled plugin entries of cfg, read from
// configPath. It returns nil, touching nothing on disk, when no entry is
// enabled for an agent.
func newEnginePlugins(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *enginePlugins {
	if len(configuredPlugins(cfg)) == 0 {
		return nil
	}
	return newEnginePluginsFor(cfg, configPath, o, log)
}

// configuredPlugins are cfg's enabled entries that list an agent, in config
// order.
func configuredPlugins(cfg config.Config) []config.Plugin {
	configured := make([]config.Plugin, 0, len(cfg.Plugins))
	for _, p := range cfg.Plugins {
		if p.Enabled && len(p.Agents) > 0 {
			configured = append(configured, p)
		}
	}
	return configured
}

// newEnginePluginsFor is newEnginePlugins, also when no entry is enabled:
// a same-user engine keeps one so it can start an entry approved while it
// runs (pluginWatch).
func newEnginePluginsFor(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *enginePlugins {
	configured := configuredPlugins(cfg)
	if o.goos == "" {
		o.goos = runtime.GOOS
	}
	if o.clock == nil {
		o.clock = plugin.RealClock()
	}
	ep := &enginePlugins{
		host: plugin.NewHost(), log: log, o: o, configured: configured,
		mode:  plugin.ModeSameUser,
		first: map[plugin.EntryKey]plugin.Verified{}, notTrusted: map[plugin.EntryKey]error{}, refused: map[plugin.EntryKey]string{},
		approval: map[plugin.EntryKey]bool{}, startChecks: map[plugin.EntryKey]entryCheck{},
	}
	if cfg.Service() {
		ep.mode = plugin.ModeService
		ep.initServiceUnits(cfg, configPath)
	}
	ep.sup = plugin.NewSupervisor(ep.host, ep.dial, o.clock).WithLog(log)
	dir := filepath.Dir(configPath)
	root, rootErr := plugin.Root(ep.mode, o.goos, dir)
	trust, trustErr := plugin.NewTrustStore(ep.mode, o.goos, dir)
	ep.root, ep.trust = root, trust
	ep.rootErr = errors.Join(rootErr, trustErr)
	for _, p := range configured {
		k := p.Key()
		required := cfg.PluginRequiresApproval(p)
		ep.approval[k] = required
		c := ep.check(p, required)
		ep.startChecks[k] = c
		switch {
		case c.notTrusted != nil:
			ep.notTrusted[k] = c.notTrusted
		case c.refused != "":
			ep.refused[k] = c.refused
		default:
			ep.first[k] = c.v
			ep.entries = append(ep.entries, c.e)
		}
	}
	if ep.mode == plugin.ModeService {
		ep.checkServiceAgents(cfg)
	}
	if ep.mode == plugin.ModeSameUser && slices.ContainsFunc(ep.entries, func(e plugin.Entry) bool { return !e.Manifest.Endpoint.IsRemote() }) {
		log.Warn("local plugins run as the engine's own OS user: same-user mode is no security boundary, and a plugin can read whatever the engine can")
	}
	return ep
}

// entryCheck is what verification found of one configured entry: the
// verified copy and the entry to run (with no agent when it requires
// approval: servedAgentsLocked grants them), or why it is not started.
type entryCheck struct {
	v          plugin.Verified
	e          plugin.Entry
	notTrusted error
	refused    string
}

// check verifies entry p's installed copy, at start and when the engine
// sees p new or changed while it runs, and decides whether it may run on
// this engine. It logs a failure.
func (ep *enginePlugins) check(p config.Plugin, required bool) entryCheck {
	k := p.Key()
	if ep.rootErr != nil {
		ep.log.Error("plugin not started: it cannot be verified", "plugin", k.String(), "err", ep.rootErr)
		return entryCheck{notTrusted: ep.rootErr}
	}
	v, err := plugin.Verify(ep.root, k, p.ManifestSHA256, ep.trust, ep.mode, plugin.RequireApproval(required))
	if err != nil {
		ep.log.Error("plugin not started: it failed verification", "plugin", k.String(), "check", verifyFailure(err))
		return entryCheck{notTrusted: err}
	}
	e, err := p.Entry(v.Manifest)
	if err != nil {
		ep.log.Error("plugin not started", "plugin", k.String(), "err", err)
		return entryCheck{refused: whyBadEntry}
	}
	if why := ep.localRefusal(p, v); why != "" {
		ep.log.Error("plugin not started: "+why, "plugin", k.String())
		return entryCheck{refused: why}
	}
	if required {
		// Served to no agent until its approval matched (servedAgentsLocked).
		e.Agents = nil
	}
	return entryCheck{v: v, e: e}
}

// startCheck is entry k's check at start, false when it was not checked
// (not enabled, or with no agent).
func (ep *enginePlugins) startCheck(k plugin.EntryKey) (entryCheck, bool) {
	c, ok := ep.startChecks[k]
	return c, ok
}

// verifyFailure is what the engine logs of a failed verification: the
// failed check in fixed words, never a path a plugin could have named
// (plugin.VerifyFailure).
func verifyFailure(err error) string {
	var ve *plugin.VerifyError
	if errors.As(err, &ve) {
		return plugin.VerifyFailure(ve)
	}
	return err.Error()
}

// localRefusal is why local entry p, verified as v, may not run on this
// engine, "" when it may. As root it never runs at all. In service mode it
// runs only under its own OS user and unit, which the engine connects to,
// so it never runs with the engine's privileges (it could read the
// engine's keys and credentials).
func (ep *enginePlugins) localRefusal(p config.Plugin, v plugin.Verified) string {
	switch {
	case v.Manifest.Endpoint.IsRemote():
		return ""
	case ep.o.euid == 0:
		return whyLocalAsRoot
	case ep.mode == plugin.ModeService:
		return ep.serviceRefusal(p, v)
	}
	return ""
}

// run supervises the started entries until ctx is done and every one has
// stopped.
func (ep *enginePlugins) run(ctx context.Context) {
	if err := ep.start(ctx); err != nil {
		return
	}
	ep.sup.Wait()
}

// start starts supervising the entries the start's checks serve, until ctx
// is done; entries the engine starts while it runs are added to the same
// supervisor (pluginWatch).
func (ep *enginePlugins) start(ctx context.Context) error {
	ep.mu.Lock()
	entries := slices.Clone(ep.entries)
	ep.mu.Unlock()
	if err := ep.sup.Start(ctx, entries); err != nil {
		ep.log.Error("plugins not started", "err", err)
		return err
	}
	return nil
}

// dial verifies e's installed copy again, so a copy changed while the
// engine runs is never started, and reaches it.
func (ep *enginePlugins) dial(ctx context.Context, e plugin.Entry) (plugin.Transport, error) {
	k := e.Key
	v, err := ep.verified(k)
	if err != nil {
		ep.log.Error("plugin not started: it failed verification", "plugin", k.String(), "check", verifyFailure(err))
		return nil, err
	}
	var t plugin.Transport
	if u, ok := ep.targets[k]; ok {
		if err := ep.recheckUnit(k, v, u); err != nil {
			ep.log.Error("plugin not started: its service unit changed", "plugin", k.String(), "err", err)
			return nil, err
		}
		// The unit is checked again on every connection the transport
		// opens, not only this first one.
		t, err = dial.Service(ctx, k, v, u.socket, u.uid, u.gid, func() error { return ep.recheckUnit(k, v, u) })
		ep.mu.Lock()
		if ep.dialWhy == nil {
			ep.dialWhy = map[plugin.EntryKey]string{}
		}
		ep.dialWhy[k] = dialFailure(err)
		ep.mu.Unlock()
	} else {
		t, err = dial.Entry(ctx, k, v, dial.Options{SocketBase: ep.o.SocketBase, CredentialFile: ep.credentialFile(k), Stderr: ep.o.Stderr, Runs: ep.o.runs})
	}
	if err != nil {
		ep.log.Warn("plugin did not start", "plugin", k.String(), "err", err)
		return nil, err
	}
	return t, nil
}

func (ep *enginePlugins) verified(k plugin.EntryKey) (plugin.Verified, error) {
	ep.mu.Lock()
	v, ok := ep.first[k]
	delete(ep.first, k)
	ep.mu.Unlock()
	if ok {
		return v, nil
	}
	ep.mu.Lock()
	sum, required := ep.configuredLocked(k).ManifestSHA256, ep.approval[k]
	ep.mu.Unlock()
	v, err := plugin.Verify(ep.root, k, sum, ep.trust, ep.mode, plugin.RequireApproval(required))
	ep.mu.Lock()
	if err != nil {
		ep.notTrusted[k] = err
	} else {
		delete(ep.notTrusted, k)
	}
	ep.mu.Unlock()
	return v, err
}

func (ep *enginePlugins) configuredEntry(k plugin.EntryKey) config.Plugin {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.configuredLocked(k)
}

// configuredLocked is the configured entry k; ep.mu is held. While the
// engine runs, pluginWatch replaces the configured entries.
func (ep *enginePlugins) configuredLocked(k plugin.EntryKey) config.Plugin {
	i := slices.IndexFunc(ep.configured, func(p config.Plugin) bool { return p.Key() == k })
	if i < 0 {
		return config.Plugin{}
	}
	return ep.configured[i]
}

func (ep *enginePlugins) credentialFile(k plugin.EntryKey) string {
	return ep.configuredEntry(k).CredentialFile()
}

// PluginProblems implements agent.PluginReporter: for each enabled entry
// that lists name, PLUGIN_NOT_TRUSTED when it failed verification, else
// PLUGIN_UNAVAILABLE when it is not READY. Messages name the entry and the
// failed check or failure class only, never another agent. While engine.json
// holds plugins the engine cannot read, every agent also gets
// PLUGIN_CONFIG_INVALID.
func (ep *enginePlugins) PluginProblems(name string) []agent.PluginProblem {
	var out []agent.PluginProblem
	ep.mu.Lock()
	configured, configProblem := slices.Clone(ep.configured), ep.configProblem
	ep.mu.Unlock()
	if configProblem != "" {
		out = append(out, agent.PluginProblem{Code: agent.ProblemPluginConfigInvalid, Message: configProblem})
	}
	for _, p := range configured {
		if !slices.Contains(p.Agents, name) {
			continue
		}
		k := p.Key()
		prob := agent.PluginProblem{Code: agent.ProblemPluginUnavailable, Name: k.Name, Instance: k.Instance}
		ep.mu.Lock()
		notTrusted, refused, dialWhy := ep.notTrusted[k], ep.refused[k], ep.dialWhy[k]
		ep.mu.Unlock()
		withheld := ep.unrecordedFor(k, name)
		switch {
		case notTrusted != nil:
			prob.Code, prob.Message = agent.ProblemPluginNotTrusted, plugin.NotTrustedMessage(k, notTrusted, name)
		case refused != "":
			prob.Message = "plugin " + k.String() + " was not started: " + refused
		case withheld.why != "":
			if withheld.code != "" {
				prob.Code = withheld.code
			}
			prob.Message = "plugin " + k.String() + " is not served to this agent: " + withheld.why
		case ep.host.State(k) == plugin.StateReady:
			continue
		default:
			prob.Message = "plugin " + k.String() + " is not ready"
			if c := ep.sup.Failure(k); c != "" {
				prob.Message += " (" + string(c) + ")"
			}
			if dialWhy != "" {
				prob.Message += ": " + dialWhy
			}
		}
		out = append(out, prob)
	}
	return out
}

// pluginDebugWriter is where --plugin-debug sends local plugins' stderr: the
// foreground engine's terminal. A service engine's stderr is its log file,
// so there it is refused and plugin stderr stays discarded.
func pluginDebugWriter(cfg config.Config, w io.Writer, log *slog.Logger) io.Writer {
	if w == nil {
		return nil
	}
	if cfg.Service() {
		log.Warn("--plugin-debug is ignored: this engine runs as a service, so its stderr is a log file, and plugin output never goes to a log")
		return nil
	}
	return w
}

// pluginRunsDirName is the directory under the engine's state directory
// that holds its plugin run records.
const pluginRunsDirName = "plugin-runs"

// pluginRuns is where a same-user engine records the local plugin processes
// it starts, after reaping what an earlier run of it left: processes still
// running and their socket directories (CONTRACT.md, Plugins, Transports).
// It runs under the engine lock, before any plugin starts, whether or not a
// plugin is enabled now. A service engine starts no plugin process and an
// engine run as root starts no local plugin: nil for both.
func pluginRuns(cfg config.Config, stateDir string, euid int, log *slog.Logger) *child.Runs {
	if cfg.Service() || euid == 0 || stateDir == "" {
		return nil
	}
	dir := filepath.Join(stateDir, pluginRunsDirName)
	child.Reap(dir, log)
	return &child.Runs{Dir: dir}
}

// engineEUID is the engine's effective user id.
func engineEUID() int { return os.Geteuid() }
