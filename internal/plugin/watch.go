package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
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
// (Plugins.check, writeAgentPluginEvents, servedAgentsLocked), and
// makes the supervisor run that. An entry that does not require approval is
// started and changed at engine start only; while the engine runs it only
// narrows (turned off, removed, an agent removed).
type pluginWatch struct {
	ep      *Plugins
	start   config.Config
	path    string
	ledgers map[string]AgentLedger
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
	checks map[pluginmodel.EntryKey]cachedCheck
	// next is when the agents are checked again; zero: only when
	// engine.json changes.
	next time.Time
	// backoff is, per agent whose database did not answer, when it is
	// checked again.
	backoff map[string]agentBackoff
	// running is what the supervisor runs: each entry and the configured
	// entry it was started from.
	running map[pluginmodel.EntryKey]runningEntry
	// trust is the trust store as read at start: an entry that does not
	// require approval rests on it, and changes to it take effect at the
	// next start.
	trust trustWant
	// retry: a PLUGIN_DISABLED could not be written; the next check writes
	// it.
	retry bool
	// On a same-user engine that keeps entries of its own: base is the
	// config entries last read from engine.json (effective), and keptRaw
	// the entries file last applied. A change of the entries file applies
	// over base also while engine.json cannot be read: request_plugin's
	// changes never wait on a hand edit.
	base    *config.Config
	keptRaw []byte
	// onDisk are the entries engine.json held at its last read through
	// Ports.ReadConfig that returned its bytes (the start's before any),
	// read leniently (heldEntries): the engine-kept entries never take a
	// (name, instance) they hold (reloadKept).
	onDisk []config.Plugin
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
	e pluginmodel.Entry
	p config.Plugin
	// approvals is, for an entry that requires approval, the approval each
	// agent is served on.
	approvals map[string]uuid.UUID
}

// newPluginWatch watches for ep, started from cfg read at path, with the
// agents' ledgers. What runs is what the start's checks served.
func newPluginWatch(ep *Plugins, cfg config.Config, path string, ledgers map[string]AgentLedger) *pluginWatch {
	w := &pluginWatch{
		ep: ep, start: cfg, path: path, ledgers: ledgers, log: ep.log, now: time.Now,
		eff: cfg, checks: map[pluginmodel.EntryKey]cachedCheck{}, backoff: map[string]agentBackoff{},
		running: map[pluginmodel.EntryKey]runningEntry{}, trust: trustedKeys(ep.o.Ports.Files, cfg, path, ep.log),
		onDisk: cfg.Plugins,
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for _, e := range ep.entries {
		w.running[e.Key] = runningEntry{e: e, p: ep.configuredLocked(e.Key), approvals: maps.Clone(ep.approvedBy[e.Key])}
	}
	return w
}

// run reads engine.json every pluginWatchTick until ctx is done.
func (w *pluginWatch) run(ctx context.Context, clock Clock) {
	for {
		var reply chan struct{}
		select {
		case <-ctx.Done():
			return
		case <-clock.After(pluginWatchTick):
		case reply = <-w.ep.kick:
		}
		w.step(ctx)
		w.publishServing()
		if reply != nil {
			close(reply)
		}
	}
}

// step is one tick: a pass when engine.json changed or the agents are due.
// engine.json that cannot be read or fails validation changes nothing: no
// pass runs until it can be read again, and status says so.
func (w *pluginWatch) step(ctx context.Context) {
	if w.serviceKept() {
		w.stepKept(ctx)
		return
	}
	// One read, the engine's own (Ports.ReadConfig): as root, the hardened
	// read, which refuses a link, a file another user owns or one group or
	// others can write. Its bytes are the change check, and its entries the
	// ones the engine-kept entries must not take (onDisk). The plugin
	// package reads engine.json through Ports.ReadConfig only
	// (TestPluginReadsEngineConfigOnlyThroughPort).
	cfg, raw, readErr := w.ep.o.Ports.ReadConfig(w.ep.o.euid, w.path)
	w.held(raw)
	if readErr != nil {
		raw = nil
	}
	var kept []byte
	if w.ep.kept != nil {
		var err error
		if kept, err = w.ep.o.Ports.Files.ReadFile(w.ep.kept.EntriesPath()); err != nil {
			kept = []byte(err.Error())
		}
	}
	keptChanged := w.ep.kept != nil && (w.keptRaw == nil || !bytes.Equal(kept, w.keptRaw))
	if w.raw == nil || !bytes.Equal(raw, w.raw) {
		w.raw = raw
		if readErr != nil {
			// Read again on every tick, until a read succeeds.
			w.raw = nil
			if !w.bad {
				w.log.Error("engine.json changed and its plugins cannot be read; no plugin change is applied until it can", "err", readErr)
			}
			w.bad = true
			w.ep.setConfigProblem(true)
			w.applyKept(ctx, kept, keptChanged)
			return
		}
		if w.bad {
			w.log.Info("engine.json can be read again; applying its plugin changes")
		}
		w.bad = false
		w.ep.setConfigProblem(false)
		w.eff = w.effective(cfg)
		if w.ep.kept != nil {
			base := w.eff
			w.base, w.keptRaw = &base, kept
			w.eff = w.ep.reloadKept(w.eff, w.onDisk)
		}
		w.pass(ctx, true)
		return
	}
	if w.bad || keptChanged {
		w.applyKept(ctx, kept, keptChanged)
		return
	}
	if !w.bad && !w.next.IsZero() && !w.now().Before(w.next) {
		w.pass(ctx, false)
	}
}

// held sets onDisk from engine.json's bytes as Ports.ReadConfig returned
// them; nil bytes (the read refused the file) or bytes that do not decode
// keep the last.
func (w *pluginWatch) held(raw []byte) {
	if raw == nil {
		return
	}
	if entries, err := heldEntries(raw); err == nil {
		w.onDisk = entries
	}
}

// applyKept applies a change of the engine-kept entries while engine.json
// cannot be read: over the config entries last read (the start's before
// any), which keep running or stopped as they were.
func (w *pluginWatch) applyKept(ctx context.Context, kept []byte, changed bool) {
	if !changed {
		return
	}
	base := w.start
	if w.base != nil {
		base = *w.base
	}
	w.keptRaw = kept
	w.eff = w.ep.reloadKept(base, w.onDisk)
	w.pass(ctx, true)
}

// serviceKept reports a service engine that keeps entries of its own: only
// those change while it runs. A same-user engine that keeps entries (an
// agent-operated one) applies its config entries while it runs too.
func (w *pluginWatch) serviceKept() bool {
	return w.ep.kept != nil && w.ep.mode == pluginmodel.ModeService
}

// stepKept is step on a service engine: only its engine-kept entries change
// while it runs (config entries are read at start only, as before). A pass
// runs when the entries file or engine.json (for a name clash) changed, or
// the agents are due.
func (w *pluginWatch) stepKept(ctx context.Context) {
	raw, err := w.ep.o.Ports.Files.ReadFile(w.ep.kept.EntriesPath())
	if err != nil {
		raw = []byte(err.Error())
	}
	// engine.json through the engine's own read (Ports.ReadConfig), for
	// its change and the entries it holds; a file that read refused adds
	// nothing and keeps the entries of the last read.
	if _, cfgRaw, _ := w.ep.o.Ports.ReadConfig(w.ep.o.euid, w.path); cfgRaw != nil {
		raw = append(append(raw, 0), cfgRaw...)
		w.held(cfgRaw)
	}
	if w.raw == nil || !bytes.Equal(raw, w.raw) {
		w.raw = raw
		w.eff = w.ep.reloadKept(w.start, w.onDisk)
		w.pass(ctx, true)
		return
	}
	if !w.next.IsZero() && !w.now().Before(w.next) {
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
	// Read once: ep.mu is held where it is asked below.
	frozen := w.frozenNow()
	configured := configuredPlugins(w.eff)
	approval := make(map[pluginmodel.EntryKey]bool, len(configured))
	checks := make(map[pluginmodel.EntryKey]entryCheck, len(configured))
	fresh := map[pluginmodel.EntryKey]bool{}
	for _, p := range configured {
		k := p.Key()
		required := ep.requires(w.start, p)
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
	narrowed := map[pluginmodel.EntryKey]runningEntry{}
	for k, r := range w.running {
		if frozen(k) {
			narrowed[k] = r
			continue
		}
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
	copyOf := func(k pluginmodel.EntryKey) (pluginmodel.Verified, bool) {
		c, ok := checks[k]
		return c.v, ok && c.ok()
	}
	want := w.wanted(copyOf)
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

	desired := map[pluginmodel.EntryKey]runningEntry{}
	kept := map[pluginmodel.EntryKey][]string{}
	waiting := false
	ep.mu.Lock()
	for _, p := range configured {
		k := p.Key()
		if frozen(k) {
			if r, ok := w.running[k]; ok {
				desired[k] = r
			}
			continue
		}
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
				return u.key == k && u.code == problemPluginAwaitingApproval
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
	ep.setWithheldLocked(passes, nil, frozen)
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

// frozenNow reports whether an entry is a service engine's config entry: it is
// run as the start decided until the engine stops (CONTRACT.md, Plugin
// changes while the engine runs: in service mode the engine reads plugins at
// start only), and the watch neither checks it nor changes it.
func (w *pluginWatch) frozenNow() func(pluginmodel.EntryKey) bool {
	if !w.serviceKept() {
		return func(pluginmodel.EntryKey) bool { return false }
	}
	// The start config's entries, as wanted holds them: an engine-kept
	// entry just removed or clashed is not one, so it narrows at once.
	start := make(map[pluginmodel.EntryKey]bool, len(w.start.Plugins))
	for _, p := range w.start.Plugins {
		start[p.Key()] = true
	}
	return func(k pluginmodel.EntryKey) bool { return start[k] }
}

// wanted is what each agent should have on record for the entries the
// watch decides. On a service engine those are its engine-kept entries
// only: its config entries are held as they are, so a pass never writes,
// ends or withholds anything of theirs.
func (w *pluginWatch) wanted(copyOf func(pluginmodel.EntryKey) (pluginmodel.Verified, bool)) pluginWant {
	ep := w.ep
	if !w.serviceKept() {
		return wantedFrom(w.eff, copyOf, ep.mode, ep.o.goos, PluginNetwork, w.trust, ep.isKept)
	}
	eff := w.eff
	eff.Plugins = slices.DeleteFunc(slices.Clone(w.eff.Plugins), func(p config.Plugin) bool { return !ep.isKept(p.Key()) })
	want := wantedFrom(eff, copyOf, ep.mode, ep.o.goos, PluginNetwork, w.trust, ep.isKept)
	want.frozen = map[pluginmodel.EntryKey]bool{}
	for _, p := range w.start.Plugins {
		k := p.Key()
		want.frozen[k] = true
		for _, a := range p.Agents {
			if held, ok := want.held[a]; ok {
				held[k] = true
			}
		}
	}
	return want
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
func (w *pluginWatch) apply(desired map[pluginmodel.EntryKey]runningEntry) {
	var stop []pluginmodel.EntryKey
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
			if !errors.Is(err, ErrNotRunning) { // the engine is stopping
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
	entries := make([]pluginmodel.Entry, 0, len(w.running))
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
func (p agentPass) undecided(k pluginmodel.EntryKey) bool {
	return slices.ContainsFunc(p.withheld, func(u unrecordedEntry) bool { return u.key == k && u.transient })
}

func configuredPlugin(configured []config.Plugin, k pluginmodel.EntryKey) (config.Plugin, bool) {
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
func (ep *Plugins) setConfigProblem(on bool) {
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
func (ep *Plugins) Serve(ctx context.Context, cfg config.Config, configPath string, ledgers map[string]AgentLedger) {
	if err := ep.start(ctx); err != nil {
		return
	}
	// The notifier hooks follow what is served; they stop before the
	// plugins drain.
	f := newPluginFeed(ep.host, ep.servedEntries, ledgers, ep.o.stateDir, ep.o.Ports.WriteFeedCursor, ep.o.Ports.ReadFeedCursor, ep.senders, ep.o.clock, ep.log)
	if ep.o.feedTiming != nil {
		f.timing = *ep.o.feedTiming
	}
	var feed sync.WaitGroup
	feed.Go(func() { f.run(ctx) })
	feed.Go(func() { ep.delivery.run(ctx, ledgers) })
	if ep.mode == pluginmodel.ModeSameUser || ep.kept != nil {
		w := newPluginWatch(ep, cfg, configPath, ledgers)
		w.publishServing()
		w.run(ctx, ep.o.clock)
	}
	feed.Wait()
	ep.sup.Wait()
}

// servedEntries are the entries the engine runs now, each with the agents
// it is served to.
func (ep *Plugins) servedEntries() []pluginmodel.Entry {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return slices.Clone(ep.entries)
}

// PluginServing is what the running engine serves, as the watch last
// published it: PLUGIN_LIST reads it (servingOf).
type PluginServing struct {
	Entries []PluginServingEntry `json:"entries"`
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

// publishServing publishes what runs for PLUGIN_LIST.
func (w *pluginWatch) publishServing() {
	st := PluginServing{Entries: []PluginServingEntry{}}
	for _, k := range slices.SortedFunc(maps.Keys(w.running), compareEntryKeys) {
		r := w.running[k]
		e := PluginServingEntry{
			Name: k.Name, Instance: k.Instance, ManifestSHA256: r.p.ManifestSHA256,
			Ready: w.ep.host.State(k) == StateReady, Agents: []PluginServingAgent{},
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
	w.ep.mu.Lock()
	w.ep.serving = st
	w.ep.mu.Unlock()
}
