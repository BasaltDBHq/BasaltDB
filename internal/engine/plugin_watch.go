package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Timing of the plugin watch (CONTRACT.md, Plugins, Plugin changes while
// the engine runs).
const (
	// pluginWatchTick is how often the engine reads engine.json.
	pluginWatchTick = time.Second
	// pluginWaitingPoll is how often each agent's plugin approvals are read
	// while an entry that requires approval is not served to one of its
	// agents; pluginRecheckPoll while every such entry is served.
	pluginWaitingPoll = 2 * time.Second
	pluginRecheckPoll = 15 * time.Second
	// pluginWatchTimeout bounds one agent's check in a pass.
	pluginWatchTimeout = 5 * time.Second
	// An agent whose database does not answer is checked again after
	// pluginWaitingPoll, doubling up to pluginWatchMaxBackoff.
	pluginWatchMaxBackoff = time.Minute
)

// pluginWatch applies plugin changes while a same-user engine runs: an entry
// that requires approval starts once its approval is signed, and any entry
// stops once it is turned off, removed, or no longer matches. It is one
// goroutine, level-triggered: each pass derives what should run from
// engine.json and the agents' ledgers, by the same checks as at start
// (enginePlugins.check, writeAgentPluginEvents, servedAgentsLocked), and
// makes the supervisor run that. An entry that does not require approval is
// started and changed at engine start only; while the engine runs it only
// narrows (turned off, removed, an agent removed).
type pluginWatch struct {
	ep      *enginePlugins
	start   config.Config
	path    string
	ledgers map[string]pluginLedger
	log     *slog.Logger
	now     func() time.Time

	// raw is engine.json as last read; bad is set while it cannot be read.
	raw []byte
	bad bool
	// eff is the config last applied: the start config with the plugins
	// of engine.json as effective (effective).
	eff config.Config
	// checks is each configured entry's verification, kept while its entry
	// is unchanged so a pass does not hash its files again.
	checks map[plugin.EntryKey]cachedCheck
	// next is when the agents are checked again; zero: only when
	// engine.json changes.
	next time.Time
	// backoff is, per agent whose database did not answer, when it is
	// checked again.
	backoff map[string]agentBackoff
	// running is what the supervisor runs: each entry and the configured
	// entry it was started from.
	running map[plugin.EntryKey]runningEntry
	// trust is the trust store as read at start: an entry that does not
	// require approval rests on it, and changes to it take effect at the
	// next start.
	trust trustWant
	// retry: a PLUGIN_DISABLED could not be written; the next check writes
	// it.
	retry bool
	// serving is PluginServingFile as last written.
	serving []byte
}

type cachedCheck struct {
	p        config.Plugin
	required bool
	c        entryCheck
}

type agentBackoff struct {
	wait  time.Duration
	until time.Time
}

type runningEntry struct {
	e plugin.Entry
	p config.Plugin
	// approvals is, for an entry that requires approval, the approval each
	// agent is served on.
	approvals map[string]uuid.UUID
}

// newPluginWatch watches for ep, started from cfg read at path, with the
// agents' ledgers. What runs is what the start's checks served.
func newPluginWatch(ep *enginePlugins, cfg config.Config, path string, ledgers map[string]pluginLedger) *pluginWatch {
	w := &pluginWatch{
		ep: ep, start: cfg, path: path, ledgers: ledgers, log: ep.log, now: time.Now,
		eff: cfg, checks: map[plugin.EntryKey]cachedCheck{}, backoff: map[string]agentBackoff{},
		running: map[plugin.EntryKey]runningEntry{}, trust: trustedKeys(cfg, path, ep.log),
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for _, e := range ep.entries {
		w.running[e.Key] = runningEntry{e: e, p: ep.configuredLocked(e.Key), approvals: maps.Clone(ep.approvedBy[e.Key])}
	}
	return w
}

// run reads engine.json every pluginWatchTick until ctx is done.
func (w *pluginWatch) run(ctx context.Context, clock plugin.Clock) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-clock.After(pluginWatchTick):
		}
		w.step(ctx)
		w.writeServing()
	}
}

// step is one tick: a pass when engine.json changed or the agents are due.
// engine.json that cannot be read or fails validation changes nothing: no
// pass runs until it can be read again, and status says so.
func (w *pluginWatch) step(ctx context.Context) {
	raw, readErr := os.ReadFile(w.path)
	if readErr != nil {
		raw = nil
	}
	if w.raw == nil || !bytes.Equal(raw, w.raw) {
		w.raw = raw
		cfg, err := config.Load(w.path)
		if readErr != nil || err != nil {
			// Read again on every tick: the file may have changed between
			// the read and the load.
			w.raw = nil
			if !w.bad {
				w.log.Error("engine.json changed and its plugins cannot be read; no plugin change is applied until it can", "err", err)
			}
			w.bad = true
			w.ep.setConfigProblem(true)
			return
		}
		if w.bad {
			w.log.Info("engine.json can be read again; applying its plugin changes")
		}
		w.bad = false
		w.ep.setConfigProblem(false)
		w.eff = w.effective(cfg)
		w.pass(ctx, true)
		return
	}
	if !w.bad && !w.next.IsZero() && !w.now().Before(w.next) {
		w.pass(ctx, false)
	}
}

// effective is cfg's plugins as this engine applies them while it runs,
// with everything else from the start config (agents, mode, operatedBy:
// those take a restart). An entry that requires approval is cfg's. One that
// does not is the entry the engine started with, narrowed: turned off when
// cfg turns it off, its agents those of both; it is dropped when cfg drops
// it, adds it or makes it one that no longer requires approval.
func (w *pluginWatch) effective(cfg config.Config) config.Config {
	eff := w.start
	eff.Plugins = nil
	for _, p := range cfg.Plugins {
		if w.start.PluginRequiresApproval(p) {
			eff.Plugins = append(eff.Plugins, p)
			continue
		}
		i := w.start.PluginIndex(p.Key())
		if i < 0 || w.start.PluginRequiresApproval(w.start.Plugins[i]) {
			continue
		}
		s := w.start.Plugins[i]
		s.Enabled = s.Enabled && p.Enabled
		s.Agents = slices.DeleteFunc(slices.Clone(s.Agents), func(a string) bool { return !slices.Contains(p.Agents, a) })
		eff.Plugins = append(eff.Plugins, s)
	}
	return eff
}

// pass applies w.eff: it verifies new and changed entries, stops what the
// config no longer serves, checks the agents that are due, and runs what
// they serve.
func (w *pluginWatch) pass(ctx context.Context, configChanged bool) {
	ep := w.ep
	now := w.now()
	configured := configuredPlugins(w.eff)
	approval := make(map[plugin.EntryKey]bool, len(configured))
	checks := make(map[plugin.EntryKey]entryCheck, len(configured))
	fresh := map[plugin.EntryKey]bool{}
	for _, p := range configured {
		k := p.Key()
		required := w.start.PluginRequiresApproval(p)
		approval[k] = required
		if !required {
			// Started and changed at engine start only (effective): the
			// start's own check, never a new one against the copy or the
			// trust store as they are now.
			c, ok := ep.startCheck(k)
			if !ok {
				c = entryCheck{refused: whyStartOnly}
			}
			checks[k] = c
			continue
		}
		if c, ok := w.checks[k]; ok && c.required == required && samePluginConfig(c.p, p, true) {
			checks[k] = c.c
			continue
		}
		c := ep.check(p, required)
		w.checks[k] = cachedCheck{p: p, required: required, c: c}
		checks[k], fresh[k] = c, true
	}
	for k := range w.checks {
		if _, ok := checks[k]; !ok {
			delete(w.checks, k)
		}
	}

	// Narrow first, from the config alone: what it no longer serves stops
	// before any database is asked.
	narrowed := map[plugin.EntryKey]runningEntry{}
	for k, r := range w.running {
		p, ok := configuredPlugin(configured, k)
		if !ok || !checks[k].ok() || !samePluginConfig(r.p, p, false) {
			continue
		}
		e := r.e
		e.Agents = slices.DeleteFunc(slices.Clone(e.Agents), func(a string) bool { return !slices.Contains(p.Agents, a) })
		if len(e.Agents) > 0 {
			narrowed[k] = runningEntry{e: e, p: p, approvals: r.approvals}
		}
	}
	w.apply(narrowed)
	// Only now does a restart of an entry dial with the new config: a
	// narrowed entry runs the same copy and config as before.
	ep.mu.Lock()
	ep.configured, ep.approval = configured, approval
	for k := range ep.notTrusted {
		if _, ok := checks[k]; !ok {
			delete(ep.notTrusted, k)
		}
	}
	for k := range ep.refused {
		if _, ok := checks[k]; !ok {
			delete(ep.refused, k)
		}
	}
	for k := range fresh {
		delete(ep.notTrusted, k)
		delete(ep.refused, k)
		if c := checks[k]; c.notTrusted != nil {
			ep.notTrusted[k] = c.notTrusted
		} else if c.refused != "" {
			ep.refused[k] = c.refused
		}
	}
	ep.mu.Unlock()

	required := slices.ContainsFunc(configured, func(p config.Plugin) bool { return approval[p.Key()] })
	if !configChanged && !required && !w.retry && !w.backoffDue(now) {
		w.schedule(now, false, false)
		w.publish()
		return
	}
	var due []string
	for _, a := range w.start.Agents {
		if b, ok := w.backoff[a.Name]; ok && now.Before(b.until) {
			continue
		}
		due = append(due, a.Name)
	}
	copyOf := func(k plugin.EntryKey) (plugin.Verified, bool) {
		c, ok := checks[k]
		return c.v, ok && c.ok()
	}
	want := wantedFrom(w.eff, copyOf, ep.mode, ep.o.goos, w.trust)
	passes := checkAgents(ctx, want, w.ledgers, due, pluginWatchTimeout, w.log)
	if ctx.Err() != nil {
		return
	}
	for name, p := range passes {
		if p.unread() {
			b := w.backoff[name]
			b.wait = min(max(2*b.wait, pluginWaitingPoll), pluginWatchMaxBackoff)
			b.until = now.Add(b.wait)
			w.backoff[name] = b
			continue
		}
		delete(w.backoff, name)
	}

	desired := map[plugin.EntryKey]runningEntry{}
	kept := map[plugin.EntryKey][]string{}
	waiting := false
	ep.mu.Lock()
	for _, p := range configured {
		k := p.Key()
		c := checks[k]
		if !c.ok() {
			continue
		}
		r, running := w.running[k]
		unchanged := running && samePluginConfig(r.p, p, false)
		keep := func(a string) bool {
			pa, checked := passes[a]
			return unchanged && slices.Contains(r.e.Agents, a) && (!checked || pa.undecided(k))
		}
		agents := ep.servedAgentsLocked(k, passes, keep)
		for _, a := range p.Agents {
			if keep(a) {
				kept[k] = append(kept[k], a)
			}
			// Waiting for a signature: checked again soon.
			if pa, ok := passes[a]; ok && approval[k] && !slices.Contains(agents, a) && slices.ContainsFunc(pa.withheld, func(u unrecordedEntry) bool {
				return u.key == k && u.code == agent.ProblemPluginAwaitingApproval
			}) {
				waiting = true
			}
		}
		if len(agents) == 0 {
			continue
		}
		e := c.e
		e.Agents = agents
		d := runningEntry{e: e, p: p}
		if approval[k] {
			d.approvals = map[string]uuid.UUID{}
			for _, a := range agents {
				if id, ok := passes[a].approvalIDs[k]; ok {
					d.approvals[a] = id
				} else if id, ok := r.approvals[a]; ok {
					d.approvals[a] = id // kept: its database did not answer
				}
			}
		}
		desired[k] = d
	}
	ep.mu.Unlock()
	w.apply(desired)
	// A record that could not be written is written by the next check.
	w.retry = !writeDisables(ctx, passes, w.ledgers, pluginWatchTimeout, w.log)
	// Status changes last: an agent that reads a withhold from it acts on a
	// ledger that already records it (a new approval signed before the
	// PLUGIN_DISABLED of the old one would be ended by it).
	ep.mu.Lock()
	ep.setWithheldLocked(passes, nil)
	for k, agents := range kept {
		// What runs on for a database that did not answer is not withheld.
		for _, a := range agents {
			delete(ep.unrecorded[k], a)
		}
	}
	ep.mu.Unlock()
	w.publish()
	w.schedule(now, required, waiting)
}

// schedule sets when the agents are checked again: every
// pluginWaitingPoll while an entry waits for a signature or a record waits
// to be written again, every pluginRecheckPoll while an entry requires
// approval, else when the first agent's backoff ends; never when nothing
// is left to check (only a change of engine.json then).
func (w *pluginWatch) schedule(now time.Time, required, waiting bool) {
	switch {
	case waiting || w.retry:
		w.next = now.Add(pluginWaitingPoll)
	case required:
		w.next = now.Add(pluginRecheckPoll)
	default:
		w.next = time.Time{}
		for _, b := range w.backoff {
			if w.next.IsZero() || b.until.Before(w.next) {
				w.next = b.until
			}
		}
	}
}

// backoffDue reports whether an agent's backoff has ended.
func (w *pluginWatch) backoffDue(now time.Time) bool {
	for _, b := range w.backoff {
		if !now.Before(b.until) {
			return true
		}
	}
	return false
}

// whyStartOnly: an entry that does not require approval and was not served
// at start is started at the next start only.
const whyStartOnly = "it does not require approval, so it starts at the engine's next start"

// apply makes the supervisor run desired: it stops every running entry
// that is not desired, or desired otherwise (other agents or another
// config), all at once, then starts the new ones. A replaced entry is
// stopped before it starts again, so for a moment it serves no agent.
func (w *pluginWatch) apply(desired map[plugin.EntryKey]runningEntry) {
	var stop []plugin.EntryKey
	for k, r := range w.running {
		if d, ok := desired[k]; !ok || !sameRun(r, d) {
			stop = append(stop, k)
		}
	}
	var wg sync.WaitGroup
	for _, k := range stop {
		w.log.Info("plugin stopped: its entry changed, or it is no longer served to an agent", "plugin", k.String())
		wg.Go(func() { w.ep.sup.Stop(k) })
	}
	wg.Wait()
	for _, k := range stop {
		delete(w.running, k)
	}
	for _, k := range slices.SortedFunc(maps.Keys(desired), compareEntryKeys) {
		d := desired[k]
		if r, ok := w.running[k]; ok {
			// The same run; the approval it is served on may be a newer one.
			r.approvals = d.approvals
			w.running[k] = r
			continue
		}
		// A copy verified before the start is never used: dial verifies it
		// again now.
		w.ep.mu.Lock()
		delete(w.ep.first, k)
		w.ep.mu.Unlock()
		if err := w.ep.sup.Add(d.e); err != nil {
			if !errors.Is(err, plugin.ErrNotRunning) { // the engine is stopping
				w.log.Warn("plugin not started", "plugin", k.String(), "err", err)
			}
			continue
		}
		w.log.Info("plugin started while the engine runs", "plugin", k.String(), "agents", len(d.e.Agents))
		w.running[k] = d
	}
}

// publish records what runs as ep's entries.
func (w *pluginWatch) publish() {
	entries := make([]plugin.Entry, 0, len(w.running))
	for _, k := range slices.SortedFunc(maps.Keys(w.running), compareEntryKeys) {
		entries = append(entries, w.running[k].e)
	}
	w.ep.mu.Lock()
	w.ep.entries = entries
	w.ep.mu.Unlock()
}

// ok reports whether the entry verified and may run on this engine.
func (c entryCheck) ok() bool { return c.notTrusted == nil && c.refused == "" }

// undecided reports whether nothing was decided of entry k for the agent
// because its database did not answer (transientErr). While the engine
// runs, what runs then stays as it is. Any answer decides: a guard that
// refuses, is missing or too old, or an agent not admitted withholds, as at
// start.
func (p agentPass) undecided(k plugin.EntryKey) bool {
	return slices.ContainsFunc(p.withheld, func(u unrecordedEntry) bool { return u.key == k && u.transient })
}

func configuredPlugin(configured []config.Plugin, k plugin.EntryKey) (config.Plugin, bool) {
	i := slices.IndexFunc(configured, func(p config.Plugin) bool { return p.Key() == k })
	if i < 0 {
		return config.Plugin{}, false
	}
	return configured[i], true
}

// samePluginConfig reports whether two configured entries are the same, in
// every field or, without withAgents, in every field but agents.
func samePluginConfig(a, b config.Plugin, withAgents bool) bool {
	if !withAgents {
		a.Agents, b.Agents = nil, nil
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// sameRun reports whether a running entry is the desired one: the same
// configured entry and the same agents.
func sameRun(r, d runningEntry) bool {
	return samePluginConfig(r.p, d.p, false) && slices.Equal(slices.Sorted(slices.Values(r.e.Agents)), slices.Sorted(slices.Values(d.e.Agents)))
}

// setConfigProblem sets or clears PLUGIN_CONFIG_INVALID.
func (ep *enginePlugins) setConfigProblem(on bool) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.configProblem = ""
	if on {
		ep.configProblem = whyConfigInvalid
	}
}

// whyConfigInvalid is PLUGIN_CONFIG_INVALID's message: fixed words, never
// the parse error, which could quote a value.
const whyConfigInvalid = "engine.json changed and the engine cannot read its plugins (it does not parse, or it breaks a rule), " +
	"so no plugin change is applied: every plugin keeps its state until the file can be read"

// serve runs the started entries, and in same-user mode watches for plugin
// changes, until ctx is done and every plugin has stopped.
func (ep *enginePlugins) serve(ctx context.Context, cfg config.Config, configPath string, ledgers map[string]pluginLedger) {
	// A file an earlier engine left (a crash, a reused pid) never speaks
	// for this one.
	if ep.o.stateDir != "" {
		_ = os.Remove(filepath.Join(ep.o.stateDir, PluginServingFile))
	}
	if err := ep.start(ctx); err != nil {
		return
	}
	// The notifier hooks follow what is served; they stop before the
	// plugins drain.
	f := newPluginFeed(ep.host, ep.servedEntries, ledgers, ep.o.stateDir, ep.senders, ep.o.clock, ep.log)
	if ep.o.feedTiming != nil {
		f.timing = *ep.o.feedTiming
	}
	var feed sync.WaitGroup
	feed.Go(func() { f.run(ctx) })
	if ep.mode == plugin.ModeSameUser {
		w := newPluginWatch(ep, cfg, configPath, ledgers)
		w.writeServing()
		w.run(ctx, ep.o.clock)
		// Stopping: nothing is served any more, before the plugins drain.
		w.removeServing()
	}
	feed.Wait()
	ep.sup.Wait()
}

// servedEntries are the entries the engine runs now, each with the agents
// it is served to.
func (ep *enginePlugins) servedEntries() []plugin.Entry {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return slices.Clone(ep.entries)
}

// PluginServingFile is the file in a same-user engine's state directory
// that says which entries the running engine serves, to which agents, on
// which approval, and whether each answers READY (CONTRACT.md, Plugin
// changes while the engine runs). basalt plugin enable --approval-id reads
// it to wait until the plugin runs. It holds no value from a plugin or its
// config. It is advice only: nothing is served because of it.
const PluginServingFile = "plugin-serving.json"

// PluginServing is PluginServingFile's content.
type PluginServing struct {
	// EnginePID is the engine that wrote it; a reader trusts it only while
	// that engine holds the engine lock.
	EnginePID int                  `json:"enginePid"`
	Entries   []PluginServingEntry `json:"entries"`
}

// PluginServingEntry is one entry the engine runs.
type PluginServingEntry struct {
	Name           string               `json:"name"`
	Instance       string               `json:"instance"`
	ManifestSHA256 string               `json:"manifestSha256"`
	Ready          bool                 `json:"ready"`
	Agents         []PluginServingAgent `json:"agents"`
}

// PluginServingAgent is an agent an entry serves, and the approval it is
// served on ("" for an entry that does not require approval).
type PluginServingAgent struct {
	Agent      string `json:"agent"`
	ApprovalID string `json:"approvalId,omitempty"`
}

// ReadPluginServing reads PluginServingFile from stateDir.
func ReadPluginServing(stateDir string) (PluginServing, error) {
	var out PluginServing
	raw, err := os.ReadFile(filepath.Join(stateDir, PluginServingFile))
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

// writeServing writes PluginServingFile when what runs changed since the
// last write: whole, by rename, mode 0600.
func (w *pluginWatch) writeServing() {
	if w.ep.o.stateDir == "" {
		return
	}
	st := PluginServing{EnginePID: os.Getpid(), Entries: []PluginServingEntry{}}
	for _, k := range slices.SortedFunc(maps.Keys(w.running), compareEntryKeys) {
		r := w.running[k]
		e := PluginServingEntry{
			Name: k.Name, Instance: k.Instance, ManifestSHA256: r.p.ManifestSHA256,
			Ready: w.ep.host.State(k) == plugin.StateReady, Agents: []PluginServingAgent{},
		}
		for _, a := range slices.Sorted(slices.Values(r.e.Agents)) {
			sa := PluginServingAgent{Agent: a}
			if id, ok := r.approvals[a]; ok {
				sa.ApprovalID = id.String()
			}
			e.Agents = append(e.Agents, sa)
		}
		st.Entries = append(st.Entries, e)
	}
	raw, err := json.Marshal(st)
	if err != nil || bytes.Equal(raw, w.serving) {
		return
	}
	if err := writeFileAtomic(w.ep.o.stateDir, PluginServingFile, raw); err != nil {
		w.log.Warn("which plugins run could not be written to the state directory; basalt plugin enable --approval-id cannot see them", "err", err)
		return
	}
	w.serving = raw
}

// removeServing removes PluginServingFile as the engine stops.
func (w *pluginWatch) removeServing() {
	if w.ep.o.stateDir != "" {
		_ = os.Remove(filepath.Join(w.ep.o.stateDir, PluginServingFile))
	}
}

// writeFileAtomic writes name in dir whole: a temporary file renamed into
// place, mode 0600.
func writeFileAtomic(dir, name string, raw []byte) error {
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
