package engine

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// pluginEventTimeout bounds one agent's plugin events at start: reading
// its ledger and writing what changed. The agents' pools connect lazily, so
// a database that is down fails here.
const pluginEventTimeout = 15 * time.Second

// whyUnrecorded is why an entry that verified is not served to one agent.
const whyUnrecorded = "its PLUGIN_ENABLED or PLUGIN_CHANGED record could not be written to this agent's ledger; " +
	"restart the engine once the agent's database is reachable"

// pluginWant is the plugin state the engine records in each agent's ledger
// at start (CONTRACT.md, Plugins, In the ledger).
type pluginWant struct {
	// served are the entries each configured agent is served now, with the
	// detail its ledger records of each.
	served map[string]map[plugin.EntryKey]guard.PluginDetail
	// held are entries enabled and listed for an agent that this engine does
	// not start (verification failed, or it may not run here): their
	// record is left as it is, so a passing failure writes nothing.
	held map[string]map[plugin.EntryKey]bool
	// trust are the keys the person added to the trust store.
	trust []string
}

// wantedPlugins is what each agent of cfg should have on record: the
// entries ep starts (none when ep is nil), the ones it holds back, and the
// trust store's added keys.
func wantedPlugins(cfg config.Config, ep *enginePlugins, trust []string) pluginWant {
	w := pluginWant{
		served: make(map[string]map[plugin.EntryKey]guard.PluginDetail, len(cfg.Agents)),
		held:   make(map[string]map[plugin.EntryKey]bool, len(cfg.Agents)),
		trust:  trust,
	}
	for _, a := range cfg.Agents {
		w.served[a.Name], w.held[a.Name] = map[plugin.EntryKey]guard.PluginDetail{}, map[plugin.EntryKey]bool{}
	}
	for _, p := range cfg.Plugins {
		if !p.Enabled {
			continue
		}
		k := p.Key()
		v, started := ep.startedCopy(k)
		for _, name := range p.Agents {
			if _, ok := w.served[name]; !ok {
				continue // the config refuses an unknown agent; never record one
			}
			if !started {
				w.held[name][k] = true
				continue
			}
			w.served[name][k] = pluginDetail(k, v, ep.mode)
		}
	}
	return w
}

// startedCopy is the verified copy of an entry ep starts, false when it
// starts none (ep nil, or the entry failed verification or was refused).
// It is read before the supervisor runs, while every started entry still
// has the copy verified at start.
func (ep *enginePlugins) startedCopy(k plugin.EntryKey) (plugin.Verified, bool) {
	if ep == nil {
		return plugin.Verified{}, false
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	v, ok := ep.first[k]
	return v, ok
}

// pluginDetail is what an agent's ledger records of entry k: the manifest's
// identity, hooks, egress and endpoint, and for a local entry its
// isolation. Never a config value, a credential, a path or an agent name.
func pluginDetail(k plugin.EntryKey, v plugin.Verified, mode plugin.Mode) guard.PluginDetail {
	m := v.Manifest
	d := guard.PluginDetail{
		Name: k.Name, Instance: k.Instance, Version: m.Version,
		ManifestSHA256: v.ManifestSHA256, SignerKeyID: v.SignerKeyID,
		Hooks:  slices.Sorted(maps.Keys(m.Hooks)),
		Egress: append([]string{}, m.Network.Egress...),
	}
	slices.Sort(d.Egress)
	if decl, ok := m.Hooks[string(plugin.HookWireDetect)]; ok && len(decl.Roles) > 0 {
		d.Roles = append([]string(nil), decl.Roles...)
		slices.Sort(d.Roles)
	}
	if r := m.Endpoint.Remote; r != nil {
		host, _ := plugin.RemoteHostPort(r.URL) // the manifest's rules checked it
		d.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: host}
		return d
	}
	d.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointLocal}
	d.Isolation = pluginIsolation(mode, m)
	return d
}

// pluginIsolation is what a local entry's record says of its isolation as
// it runs on this engine. In same-user mode it runs as the engine's own OS
// user with the engine's network: files NONE, network NOT_ENFORCED. An
// engine run as a service starts no local plugin yet (localRefusal), so no
// record says more than that. When each local entry runs under its own OS
// user and unit, this is where service mode records files OS_USER and
// network ENFORCED (empty egress, no network) or DECLARED (egress
// declared, not enforced per host), or NOT_ENFORCED where the OS cannot
// isolate the network.
func pluginIsolation(_ plugin.Mode, _ plugin.Manifest) *guard.PluginIsolation {
	return &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced}
}

// writePluginEvents records in each agent's own ledger what changed since
// the plugin events it already has: the last-seen state is the ledger's,
// so a restart with no change writes nothing and a change made while the
// engine was stopped is recorded now. For each agent:
//   - an entry it is served that its ledger shows disabled or never had:
//     PLUGIN_ENABLED;
//   - one whose detail differs from the last recorded: PLUGIN_CHANGED;
//   - one its ledger shows served that it is no longer served (disabled,
//     removed, or the agent removed from its agents) and that is not held:
//     PLUGIN_DISABLED, with the detail last recorded;
//   - each added trust key its ledger lacks: PLUGIN_TRUST_ADDED, written
//     first.
//
// Agents run in parallel, each bounded by pluginEventTimeout. It returns,
// per agent, the served entries whose record could not be written: they
// must not be served to that agent. An agent missing from dbs has no
// ledger to write to.
func writePluginEvents(ctx context.Context, want pluginWant, dbs map[string]guard.Querier, log *slog.Logger) map[string][]plugin.EntryKey {
	var mu sync.Mutex
	unrecorded := map[string][]plugin.EntryKey{}
	var wg sync.WaitGroup
	for _, name := range slices.Sorted(maps.Keys(want.served)) {
		wg.Go(func() {
			failed := writeAgentPluginEvents(ctx, name, want, dbs[name], log.With("agent", name))
			if len(failed) == 0 {
				return
			}
			mu.Lock()
			unrecorded[name] = failed
			mu.Unlock()
		})
	}
	wg.Wait()
	return unrecorded
}

// writeAgentPluginEvents is writePluginEvents for one agent; it returns the
// served entries whose record it could not write.
func writeAgentPluginEvents(ctx context.Context, name string, want pluginWant, db guard.Querier, log *slog.Logger) []plugin.EntryKey {
	served := slices.SortedFunc(maps.Keys(want.served[name]), compareEntryKeys)
	if db == nil {
		return served
	}
	ctx, cancel := context.WithTimeout(ctx, pluginEventTimeout)
	defer cancel()
	recs, err := guard.ReadPluginRecords(ctx, db)
	if err != nil {
		if len(served) > 0 {
			log.Error("plugins not served to this agent: its ledger cannot be read", "err", err)
		}
		return served
	}
	last := make(map[plugin.EntryKey]guard.PluginRecord, len(recs.Entries))
	for _, r := range recs.Entries {
		last[plugin.EntryKey{Name: r.Detail.Name, Instance: r.Detail.Instance}] = r
	}
	// Keys first: a key is trusted before an entry it signed is served.
	for _, id := range want.trust {
		if slices.Contains(recs.TrustKeys, id) {
			continue
		}
		if err := guard.RecordPluginTrustAdded(ctx, db, id); err != nil {
			log.Warn("PLUGIN_TRUST_ADDED not recorded; the next start tries again", "keyId", id, "err", err)
		}
	}
	var failed []plugin.EntryKey
	for _, k := range served {
		d := want.served[name][k]
		kind, ok := entryEvent(last, k, d)
		if !ok {
			continue
		}
		if err := guard.RecordPluginEntryEvent(ctx, db, kind, d); err != nil {
			log.Error("plugin not served to this agent: its record could not be written", "plugin", k.String(), "event", kind, "err", err)
			failed = append(failed, k)
		}
	}
	for _, r := range recs.Entries {
		k := plugin.EntryKey{Name: r.Detail.Name, Instance: r.Detail.Instance}
		if _, ok := want.served[name][k]; ok || !r.Enabled() || want.held[name][k] {
			continue
		}
		if err := guard.RecordPluginEntryEvent(ctx, db, guard.PluginDisabled, r.Detail); err != nil {
			log.Warn("PLUGIN_DISABLED not recorded; the next start tries again", "plugin", k.String(), "err", err)
		}
	}
	return failed
}

// entryEvent is the event a served entry needs given the agent's last
// records: PLUGIN_ENABLED when there is none or it was disabled,
// PLUGIN_CHANGED when the detail differs, none when it is the same.
func entryEvent(last map[plugin.EntryKey]guard.PluginRecord, k plugin.EntryKey, d guard.PluginDetail) (guard.PluginEventKind, bool) {
	r, ok := last[k]
	switch {
	case !ok || !r.Enabled():
		return guard.PluginEnabled, true
	case !sameDetail(r.Detail, d):
		return guard.PluginChanged, true
	}
	return "", false
}

// sameDetail compares two details as the ledger stores them.
func sameDetail(a, b guard.PluginDetail) bool {
	if a.Egress == nil {
		a.Egress = []string{}
	}
	if b.Egress == nil {
		b.Egress = []string{}
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

func compareEntryKeys(a, b plugin.EntryKey) int {
	return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Instance, b.Instance))
}

// addedTrustKeys are the keys the person added to the trust store of an
// engine run with cfg from configPath; none, logged, when it cannot be read.
func addedTrustKeys(cfg config.Config, configPath string, log *slog.Logger) []string {
	mode := plugin.ModeSameUser
	if cfg.Service() {
		mode = plugin.ModeService
	}
	trust, err := plugin.NewTrustStore(mode, runtime.GOOS, filepath.Dir(configPath))
	if err != nil {
		log.Warn("plugin trust keys not recorded: the trust store cannot be read", "err", err)
		return nil
	}
	keys, err := trust.AddedKeys()
	if err != nil {
		log.Warn("plugin trust keys not recorded: the trust store cannot be read", "err", err)
		return nil
	}
	return keys
}

// recordPluginEvents writes the start's plugin events (writePluginEvents)
// and withholds from each agent the entries whose record failed, before
// any plugin starts. ep is nil when no entry is enabled: removed or
// disabled entries are still recorded then.
func recordPluginEvents(ctx context.Context, cfg config.Config, configPath string, ep *enginePlugins, dbs map[string]guard.Querier, log *slog.Logger) {
	want := wantedPlugins(cfg, ep, addedTrustKeys(cfg, configPath, log))
	unrecorded := writePluginEvents(ctx, want, dbs, log)
	ep.withhold(unrecorded)
}

// withhold stops serving each agent the entries whose record could not be
// written to its ledger: the record is part of consent. The agent is taken
// out of the entry's agents (the host then refuses any call naming it),
// an entry left with no agent is not started, and status shows
// PLUGIN_UNAVAILABLE for that agent. It runs before the supervisor does.
func (ep *enginePlugins) withhold(unrecorded map[string][]plugin.EntryKey) {
	if ep == nil || len(unrecorded) == 0 {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.unrecorded == nil {
		ep.unrecorded = map[plugin.EntryKey]map[string]bool{}
	}
	for agentName, keys := range unrecorded {
		for _, k := range keys {
			if ep.unrecorded[k] == nil {
				ep.unrecorded[k] = map[string]bool{}
			}
			ep.unrecorded[k][agentName] = true
		}
	}
	kept := ep.entries[:0]
	for _, e := range ep.entries {
		e.Agents = slices.DeleteFunc(slices.Clone(e.Agents), func(a string) bool { return ep.unrecorded[e.Key][a] })
		if len(e.Agents) > 0 {
			kept = append(kept, e)
		}
	}
	ep.entries = kept
}

// unrecordedFor reports whether entry k is withheld from agent name.
func (ep *enginePlugins) unrecordedFor(k plugin.EntryKey, name string) bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.unrecorded[k][name]
}
