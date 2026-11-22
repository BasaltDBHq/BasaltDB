package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	service "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/dial"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/keptplugins"
	"github.com/basaltdbhq/basaltdb/internal/service/person"
	plugin "github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
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
	// stateDir is where a same-user engine writes which entries it serves
	// (pluginServingFile), and where every engine keeps its feed cursors;
	// "" writes nothing and feeds no plugin.
	stateDir string
	// feedTiming replaces the feed's intervals (tests); nil is the
	// contract's.
	feedTiming *feedTiming
	// deliverTiming replaces the delivery's numbers (tests); nil is the
	// contract's.
	deliverTiming *deliverTiming
	// now is the engine's clock for the notifier hooks' expiries and try
	// times; time.Now when nil.
	now func() time.Time
	// kept is a service engine's own entries (CONTRACT.md, Plugin approval
	// in service mode); nil in same-user mode.
	kept *keptplugins.Store
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
	// senders make the notifier hooks' calls, one per served entry that
	// declares feed.observe or approval.deliver (pluginFeed keeps them in
	// step with what is served): senders.sender(k).
	senders *pluginSenders
	// delivery hands approval notices to the approval.deliver entries.
	delivery *pluginDelivery
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
	// approvedBy is, for each entry that requires approval served at start,
	// the approval each agent is served on.
	approvedBy map[plugin.EntryKey]map[string]uuid.UUID

	// A service engine's own entries: the store, which configured entries
	// are engine-kept, why the entries file cannot be used ("" when it
	// can), the engine-kept entries not served because engine.json holds
	// their (name, instance), and why no engine-kept local entry may start
	// (an agent's OS user in the engine's group).
	kept        *keptplugins.Store
	keptKeys    map[plugin.EntryKey]bool
	keptProblem string
	clashes     []config.Plugin
	groupErr    error
	// startCfg is the start config with the engine-kept entries added.
	startCfg config.Config
	// kick asks the watch to apply a change now (applyNow).
	kick chan chan struct{}
	// serving is what runs, as the watch last published it.
	serving PluginServing
}

// newEnginePlugins verifies the enabled plugin entries of cfg, read from
// configPath. It returns nil, touching nothing on disk, when no entry is
// enabled for an agent.
func newEnginePlugins(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *enginePlugins {
	if len(configuredPlugins(cfg)) == 0 && o.kept == nil {
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
	if o.goos == "" {
		o.goos = runtime.GOOS
	}
	if o.clock == nil {
		o.clock = plugin.RealClock()
	}
	ep := &enginePlugins{
		host: plugin.NewHost(), log: log, o: o,
		mode:  plugin.ModeSameUser,
		first: map[plugin.EntryKey]plugin.Verified{}, notTrusted: map[plugin.EntryKey]error{}, refused: map[plugin.EntryKey]string{},
		approval: map[plugin.EntryKey]bool{}, startChecks: map[plugin.EntryKey]entryCheck{},
		keptKeys: map[plugin.EntryKey]bool{}, kick: make(chan chan struct{}), startCfg: cfg,
	}
	if cfg.Service() {
		ep.mode = plugin.ModeService
		ep.initServiceUnits(cfg, configPath)
		if o.kept != nil {
			ep.kept = o.kept
			ep.groupErr = ep.agentsInEngineGroup(cfg)
			ep.startCfg = ep.reloadKept(cfg, configPath)
		}
	} else if o.kept != nil {
		// An agent-operated engine on the bot's computer: its engine-kept
		// entries run as its own children, as every local plugin does in
		// same-user mode, and its config entries change while it runs.
		ep.kept = o.kept
		ep.startCfg = ep.reloadKept(cfg, configPath)
	}
	configured := configuredPlugins(ep.startCfg)
	ep.configured = configured
	ep.sup = plugin.NewSupervisor(ep.host, ep.dial, o.clock).WithLog(log)
	if o.now == nil {
		o.now = time.Now
		ep.o.now = o.now
	}
	ep.senders = newPluginSenders(ep.host, o.now)
	ep.delivery = newPluginDelivery(ep.host, ep.servedEntries, ep.senders, o.now, o.clock, log)
	if o.deliverTiming != nil {
		ep.delivery.timing = *o.deliverTiming
	}
	dir := filepath.Dir(configPath)
	root, rootErr := plugin.Root(ep.mode, o.goos, dir)
	trust, trustErr := plugin.NewTrustStore(ep.mode, o.goos, dir)
	ep.root, ep.trust = root, trust
	ep.rootErr = errors.Join(rootErr, trustErr)
	for _, p := range configured {
		k := p.Key()
		required := ep.requires(cfg, p)
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
	kept := ep.isKept(k)
	if ep.rootErr != nil && !kept {
		ep.log.Error("plugin not started: it cannot be verified", "plugin", k.String(), "err", ep.rootErr)
		return entryCheck{notTrusted: ep.rootErr}
	}
	v, err := ep.verifyCopy(k, p.ManifestSHA256, required)
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
	case ep.isKept(p.Key()):
		// The engine runs an approved engine-kept local entry itself, as
		// its own OS user, as a same-user engine does.
		if ep.groupErr != nil {
			return whyKeptAgentInGroup
		}
		return ""
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
	v, err := ep.verifyCopy(k, sum, required)
	ep.mu.Lock()
	if err != nil {
		ep.notTrusted[k] = err
	} else {
		delete(ep.notTrusted, k)
	}
	ep.mu.Unlock()
	return v, err
}

// verifyCopy verifies entry k's installed copy: an engine-kept entry's
// under the state directory, always as one that requires approval; any
// other under the plugin root of the engine's mode.
func (ep *enginePlugins) verifyCopy(k plugin.EntryKey, sum string, required bool) (plugin.Verified, error) {
	if ep.isKept(k) {
		return ep.kept.Verify(k, sum)
	}
	return plugin.Verify(ep.root, k, sum, ep.trust, ep.mode, plugin.RequireApproval(required))
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
	keptProblem, clashes := ep.keptProblem, slices.Clone(ep.clashes)
	ep.mu.Unlock()
	if configProblem != "" {
		out = append(out, agent.PluginProblem{Code: agent.ProblemPluginConfigInvalid, Message: configProblem})
	}
	if keptProblem != "" {
		out = append(out, agent.PluginProblem{
			Code: agent.ProblemPluginUnavailable, Message: "no engine-kept plugin is served: " + keptProblem, File: ep.kept.EntriesPath(),
		})
	}
	for _, p := range clashes {
		if slices.Contains(p.Agents, name) {
			k := p.Key()
			out = append(out, agent.PluginProblem{
				Code: agent.ProblemPluginUnavailable, Name: k.Name, Instance: k.Instance, EngineKept: true,
				Message: "the engine-kept plugin " + k.String() + " is not served: engine.json holds an entry of the same name and instance, " +
					"added by hand, and that one is served; remove one of them (the agent removes the engine-kept one with request_plugin, or the person edits engine.json)",
			})
		}
	}
	for _, p := range configured {
		if !slices.Contains(p.Agents, name) {
			continue
		}
		k := p.Key()
		prob := agent.PluginProblem{Code: agent.ProblemPluginUnavailable, Name: k.Name, Instance: k.Instance, EngineKept: ep.isKept(k)}
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
	for _, dn := range ep.delivery.dropped(name) {
		out = append(out, agent.PluginProblem{
			Code: agent.ProblemPluginNoticesDropped, Name: dn.key.Name, Instance: dn.key.Instance, EngineKept: ep.isKept(dn.key),
			Message: fmt.Sprintf("plugin %s did not get %s of this agent in the last 24 hours: the engine dropped them "+
				"(the plugin did not take them within about a minute, they expired first, or too many were waiting). "+
				"The agent's answers carried the links all the same", dn.key, noticeCount(dn.count)),
		})
	}
	return out
}

// PluginEntries implements agent.PluginLister: the enabled entries that list
// name, for status.plugins.
func (ep *enginePlugins) PluginEntries(name string) []agent.PluginEntry {
	ep.mu.Lock()
	configured := slices.Clone(ep.configured)
	ep.mu.Unlock()
	var out []agent.PluginEntry
	for _, p := range configured {
		if slices.Contains(p.Agents, name) {
			k := p.Key()
			out = append(out, agent.PluginEntry{Name: k.Name, Instance: k.Instance})
		}
	}
	return out
}

// DeliverLinks is the agent.LinkDeliverer of the agent named name: its
// notices go to the approval.deliver entries served to it.
func (ep *enginePlugins) DeliverLinks(name string) agent.LinkDeliverer {
	return ep.delivery.forAgent(name)
}

func noticeCount(n int) string {
	if n == 1 {
		return "1 approval notice"
	}
	return fmt.Sprintf("%d approval notices", n)
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

// engineEUID is the engine's effective user id.
func engineEUID() int { return os.Geteuid() }

// whyKeptAgentInGroup: an agent's OS user is in the engine's group, which
// reaches the engine's sockets and directories, so no engine-kept local
// entry starts (CONTRACT.md, Service units).
const whyKeptAgentInGroup = "an agent's OS user is in the engine's group, or the group cannot be checked, so the engine starts no local plugin itself"

// isKept reports whether configured entry k is engine-kept.
func (ep *enginePlugins) isKept(k plugin.EntryKey) bool {
	if ep == nil {
		return false
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.keptKeys[k]
}

// requires reports whether entry p requires approval on this engine: every
// engine-kept entry does; any other as cfg says.
func (ep *enginePlugins) requires(cfg config.Config, p config.Plugin) bool {
	return ep.isKept(p.Key()) || cfg.PluginRequiresApproval(p)
}

// agentsInEngineGroup is why no engine-kept local entry may start: an
// agent's OS user is in the engine's group, or the engine's user cannot be
// read; nil when they may.
func (ep *enginePlugins) agentsInEngineGroup(cfg config.Config) error {
	if ep.unitHostErr != nil {
		return ep.unitHostErr
	}
	users := make(map[string]string, len(cfg.Agents))
	for _, a := range cfg.Agents {
		users[a.Name] = a.OSUser
	}
	return ep.units().checkAgents(ep.unitHost.EngineUser, users)
}

// reloadKept reads the engine-kept entries and returns cfg with them added:
// the enabled ones that list an agent and whose (name, instance) engine.json
// does not hold (the start config's, or the file's now). A file that cannot
// be used adds none, and status says why.
func (ep *enginePlugins) reloadKept(cfg config.Config, configPath string) config.Config {
	entries, err := ep.kept.Entries(cfg)
	held := configKeys(cfg, configPath)
	out := cfg
	out.Plugins = slices.Clone(cfg.Plugins)
	keys := map[plugin.EntryKey]bool{}
	var clashes []config.Plugin
	problem := ""
	if err != nil {
		problem = err.Error()
		ep.log.Error("no engine-kept plugin is served: its entries file cannot be used", "err", err)
		entries = nil
	}
	for _, p := range entries {
		k := p.Key()
		if held[k] {
			clashes = append(clashes, p)
			continue
		}
		keys[k] = true
		out.Plugins = append(out.Plugins, p)
	}
	ep.mu.Lock()
	ep.keptKeys, ep.keptProblem, ep.clashes = keys, problem, clashes
	ep.mu.Unlock()
	return out
}

// configKeys are the (name, instance)s of cfg's entries and of those
// engine.json holds on disk now, read leniently.
func configKeys(cfg config.Config, configPath string) map[plugin.EntryKey]bool {
	out := map[plugin.EntryKey]bool{}
	for _, p := range cfg.Plugins {
		out[p.Key()] = true
	}
	var now struct {
		Plugins []config.Plugin `json:"plugins"`
	}
	if raw, err := os.ReadFile(configPath); err == nil && json.Unmarshal(raw, &now) == nil {
		for _, p := range now.Plugins {
			out[p.Key()] = true
		}
	}
	return out
}

// applyNow asks the watch to apply the engine-kept entries as they are now
// and waits until it has, at most kickWait; a watch that does not answer
// sees the change at its next tick.
func (ep *enginePlugins) applyNow(ctx context.Context) {
	if ep == nil {
		return
	}
	reply := make(chan struct{})
	t := time.NewTimer(kickWait)
	defer t.Stop()
	select {
	case ep.kick <- reply:
	case <-ctx.Done():
		return
	case <-t.C:
		return
	}
	select {
	case <-reply:
	case <-ctx.Done():
	case <-t.C:
	}
}

// kickWait bounds applyNow.
const kickWait = 30 * time.Second

// healthOf is what the running engine knows of the entry k, engine-kept
// (kept) or of engine.json: READY when its plugin answers; UNAVAILABLE when
// the engine runs it, or keeps trying to start it, and it does not answer;
// NOT_STARTED when the engine does not run it. The engine runs one entry
// per (name, instance): when engine.json and the engine both hold k, the
// one it does not run is NOT_STARTED. It says nothing of any agent.
func (ep *enginePlugins) healthOf(k plugin.EntryKey, kept bool) string {
	if ep == nil || ep.host == nil || ep.isKept(k) != kept {
		return person.HealthNotStarted
	}
	if ep.host.State(k) == plugin.StateReady {
		return person.HealthReady
	}
	if _, ok := ep.host.Registration(k); ok {
		return person.HealthUnavailable
	}
	// Not registered: a start or an initialize that fails registers
	// nothing, and the supervisor tries again.
	if ep.sup != nil && slices.Contains(ep.sup.Supervised(), k) {
		return person.HealthUnavailable
	}
	return person.HealthNotStarted
}

// servingOf is what the running engine serves of engine-kept entry k: each
// agent, the approval it is served on and whether the plugin answers READY.
func (ep *enginePlugins) servingOf(k plugin.EntryKey) []person.PluginServing {
	if ep == nil {
		return nil
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if !ep.keptKeys[k] {
		return nil
	}
	var out []person.PluginServing
	for _, e := range ep.serving.Entries {
		if e.Name != k.Name || e.Instance != k.Instance {
			continue
		}
		for _, a := range e.Agents {
			sv := person.PluginServing{Agent: a.Agent, Ready: e.Ready}
			if id, err := uuid.Parse(a.ApprovalID); err == nil {
				sv.ApprovalID = &id
			}
			out = append(out, sv)
		}
	}
	return out
}
