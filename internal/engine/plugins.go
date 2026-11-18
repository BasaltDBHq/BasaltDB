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
	"github.com/basaltdbhq/basaltdb/internal/plugin"
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
	// goos and euid default to the running engine's.
	goos string
	euid int
	// clock is the supervisor's; plugin.RealClock() when nil.
	clock plugin.Clock
}

// Why an entry is not started though it verified.
const (
	whyLocalInService = "a local plugin runs under its own OS user and service, which this engine does not set up yet"
	whyLocalAsRoot    = "the engine runs as root, and a local plugin is never started with root's privileges"
	whyBadEntry       = "its entry in engine.json breaks a rule (see the engine's log)"
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
}

// newEnginePlugins verifies the enabled plugin entries of cfg, read from
// configPath. It returns nil, touching nothing on disk, when no entry is
// enabled for an agent.
func newEnginePlugins(cfg config.Config, configPath string, o pluginOptions, log *slog.Logger) *enginePlugins {
	configured := make([]config.Plugin, 0, len(cfg.Plugins))
	for _, p := range cfg.Plugins {
		if p.Enabled && len(p.Agents) > 0 {
			configured = append(configured, p)
		}
	}
	if len(configured) == 0 {
		return nil
	}
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
	}
	if cfg.Service() {
		ep.mode = plugin.ModeService
	}
	ep.sup = plugin.NewSupervisor(ep.host, ep.dial, o.clock).WithLog(log)
	dir := filepath.Dir(configPath)
	root, rootErr := plugin.Root(ep.mode, o.goos, dir)
	trust, trustErr := plugin.NewTrustStore(ep.mode, o.goos, dir)
	ep.root, ep.trust = root, trust
	for _, p := range configured {
		k := p.Key()
		if err := errors.Join(rootErr, trustErr); err != nil {
			ep.notTrusted[k] = err
			log.Error("plugin not started: it cannot be verified", "plugin", k.String(), "err", err)
			continue
		}
		v, err := plugin.Verify(root, k, p.ManifestSHA256, trust, ep.mode)
		if err != nil {
			ep.notTrusted[k] = err
			log.Error("plugin not started: it failed verification", "plugin", k.String(), "check", verifyFailure(err))
			continue
		}
		e, err := p.Entry(v.Manifest)
		if err != nil {
			ep.refused[k] = whyBadEntry
			log.Error("plugin not started", "plugin", k.String(), "err", err)
			continue
		}
		if why := ep.localRefusal(v.Manifest); why != "" {
			ep.refused[k] = why
			log.Error("plugin not started: "+why, "plugin", k.String())
			continue
		}
		ep.first[k] = v
		ep.entries = append(ep.entries, e)
	}
	if ep.mode == plugin.ModeSameUser && slices.ContainsFunc(ep.entries, func(e plugin.Entry) bool { return !e.Manifest.Endpoint.IsRemote() }) {
		log.Warn("local plugins run as the engine's own OS user: same-user mode is no security boundary, and a plugin can read whatever the engine can")
	}
	return ep
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

// localRefusal is why a local plugin may not run on this engine, "" when
// it may. In service mode a local plugin needs its own OS user and unit, so
// it never runs with the engine's privileges (it could read the engine's
// keys and credentials); as root it never runs at all.
func (ep *enginePlugins) localRefusal(m plugin.Manifest) string {
	switch {
	case m.Endpoint.IsRemote():
		return ""
	case ep.mode == plugin.ModeService:
		return whyLocalInService
	case ep.o.euid == 0:
		return whyLocalAsRoot
	}
	return ""
}

// run supervises the started entries until ctx is done and every one has
// stopped.
func (ep *enginePlugins) run(ctx context.Context) {
	if len(ep.entries) == 0 {
		return
	}
	if err := ep.sup.Run(ctx, ep.entries); err != nil {
		ep.log.Error("plugins not started", "err", err)
	}
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
	t, err := dial.Entry(ctx, k, v, dial.Options{SocketBase: ep.o.SocketBase, CredentialFile: ep.credentialFile(k), Stderr: ep.o.Stderr})
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
	v, err := plugin.Verify(ep.root, k, ep.manifestSHA256(k), ep.trust, ep.mode)
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
	i := slices.IndexFunc(ep.configured, func(p config.Plugin) bool { return p.Key() == k })
	if i < 0 {
		return config.Plugin{}
	}
	return ep.configured[i]
}

func (ep *enginePlugins) manifestSHA256(k plugin.EntryKey) string {
	return ep.configuredEntry(k).ManifestSHA256
}

func (ep *enginePlugins) credentialFile(k plugin.EntryKey) string {
	return ep.configuredEntry(k).CredentialFile()
}

// PluginProblems implements agent.PluginReporter: for each enabled entry
// that lists name, PLUGIN_NOT_TRUSTED when it failed verification, else
// PLUGIN_UNAVAILABLE when it is not READY. Messages name the entry and the
// failed check or failure class only, never another agent.
func (ep *enginePlugins) PluginProblems(name string) []agent.PluginProblem {
	var out []agent.PluginProblem
	for _, p := range ep.configured {
		if !slices.Contains(p.Agents, name) {
			continue
		}
		k := p.Key()
		prob := agent.PluginProblem{Code: agent.ProblemPluginUnavailable, Name: k.Name, Instance: k.Instance}
		ep.mu.Lock()
		notTrusted, refused := ep.notTrusted[k], ep.refused[k]
		ep.mu.Unlock()
		switch {
		case notTrusted != nil:
			prob.Code, prob.Message = agent.ProblemPluginNotTrusted, plugin.NotTrustedMessage(k, notTrusted, name)
		case refused != "":
			prob.Message = "plugin " + k.String() + " was not started: " + refused
		case ep.host.State(k) == plugin.StateReady:
			continue
		default:
			prob.Message = "plugin " + k.String() + " is not ready"
			if c := ep.sup.Failure(k); c != "" {
				prob.Message += " (" + string(c) + ")"
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

// engineEUID is the engine's effective user id.
func engineEUID() int { return os.Geteuid() }
