//go:build unix

package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
)

// writeConfig writes f.cfg as engine.json, as a basalt plugin command
// writes it (whole, by rename): a config Load accepts.
func (f *pluginFixture) writeConfig() {
	f.t.Helper()
	agents := make([]map[string]any, 0, len(f.cfg.Agents))
	for _, a := range f.cfg.Agents {
		agents = append(agents, map[string]any{"name": a.Name, "osUser": a.OSUser, "store": map[string]any{"kind": "POSTGRES", "credentialFile": "/c/" + a.Name}})
	}
	m := map[string]any{"socketDir": "/run/x", "mode": "SAME_USER", "agents": agents}
	if len(f.cfg.Plugins) > 0 {
		m["plugins"] = f.cfg.Plugins
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	require.NoError(f.t, err)
	require.NoError(f.t, config.WriteFile(f.configPath, raw))
}

// pools are the agents' ledgers as the engine holds them while it runs: a
// pool each, used by the watch while the test reads and signs on its own
// connections.
func (l pluginLedgers) pools(t *testing.T) map[string]AgentLedger {
	t.Helper()
	out := map[string]AgentLedger{}
	for name, url := range l.urls {
		pool, err := pgxpool.New(context.Background(), url)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		out[name] = AgentLedger{ports: testPorts, db: pool}
	}
	return out
}

// livePlugins are a same-user engine's plugins as RunWith runs them:
// verified, recorded and started from engine.json, then watched. The test
// drives the watch: change writes engine.json and runs one tick, poll runs
// the agents' check that a tick runs when it is due.
type livePlugins struct {
	t       *testing.T
	f       *pluginFixture
	ep      *Plugins
	w       *pluginWatch
	ledgers map[string]AgentLedger
	ctx     context.Context
	stop    func()
}

func (f *pluginFixture) live(l pluginLedgers, o Options) *livePlugins {
	f.t.Helper()
	t := f.t
	f.writeConfig()
	cfg, err := config.Load(f.configPath)
	require.NoError(t, err)
	o.SocketBase, o.euid = f.sockBase, os.Geteuid()
	log := slog.New(slog.DiscardHandler)
	ep := NewFor(cfg, f.configPath, o, log)
	ledgers := l.pools(t)
	ctx, cancel := context.WithCancel(context.Background())
	RecordEvents(ctx, cfg, f.configPath, ep, ledgers, log)
	require.NoError(t, ep.start(ctx))
	lp := &livePlugins{t: t, f: f, ep: ep, w: newPluginWatch(ep, cfg, f.configPath, ledgers), ledgers: ledgers, ctx: ctx}
	stopped := false
	lp.stop = func() {
		if !stopped {
			stopped = true
			cancel()
			ep.sup.Wait()
		}
	}
	t.Cleanup(lp.stop)
	lp.w.step(ctx) // the first read of engine.json changes nothing
	return lp
}

func (lp *livePlugins) change() {
	lp.t.Helper()
	lp.f.writeConfig()
	lp.w.step(lp.ctx)
}

func (lp *livePlugins) poll() { lp.w.pass(lp.ctx, false) }

// callAs is a hook call to entry k naming agentName, as the engine makes
// it: refused before anything is sent when the entry does not serve it.
func (lp *livePlugins) callAs(k pluginmodel.EntryKey, agentName string) error {
	return lp.ep.host.Call(context.Background(), k, []string{agentName}, "feed.observe", nil, nil)
}

// requireServing: k runs and serves exactly agents.
func (lp *livePlugins) requireServing(k pluginmodel.EntryKey, agents ...string) {
	lp.t.Helper()
	slices.Sort(agents)
	require.Equal(lp.t, agents, servedTo(lp.ep, k))
	waitReady(lp.t, lp.ep, k)
	for _, a := range lp.f.cfg.Agents {
		err := lp.callAs(k, a.Name)
		if slices.Contains(agents, a.Name) {
			require.NoError(lp.t, err, a.Name)
		} else {
			require.ErrorIs(lp.t, err, pluginmodel.ErrAgentNotListed, a.Name)
		}
	}
}

// requireStopped: k runs for no agent, and its process got shutdown.
func (lp *livePlugins) requireStopped(k pluginmodel.EntryKey) {
	lp.t.Helper()
	require.Empty(lp.t, servedTo(lp.ep, k))
	require.NotContains(lp.t, lp.ep.sup.Supervised(), k)
	require.Equal(lp.t, StateUnavailable, lp.ep.host.State(k))
	for _, a := range lp.f.cfg.Agents {
		require.Error(lp.t, lp.callAs(k, a.Name))
	}
}

// startedPIDs are the test plugin processes started so far, and the ones
// that were asked to shut down.
func (f *pluginFixture) startedPIDs() (started, shutdown []int) {
	return f.reported(".start"), f.reported(".shutdown")
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// The seamless path: the engine runs with no plugin; an agent's add writes
// an entry that requires approval and opens an approval; a person signs it
// with a passkey. The engine, never restarted, starts the plugin for that
// agent within a few seconds of the signature, with its record written after
// the approval, and nobody typed anything. This runs the watch on its own
// clock, as the engine does.
func TestApprovedPluginStartsWithoutRestart(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	l := newPluginLedgers(t, f)
	f.writeConfig()
	cfg, err := config.Load(f.configPath)
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	ep := NewFor(cfg, f.configPath, Options{Ports: testPorts, Dialer: dial.Dialer{}, SocketBase: f.sockBase, euid: os.Geteuid()}, log)
	ledgers := l.pools(t)
	ctx, cancel := context.WithCancel(context.Background())
	RecordEvents(ctx, cfg, f.configPath, ep, ledgers, log)
	done := make(chan struct{})
	go func() { ep.Serve(ctx, cfg, f.configPath, ledgers); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// What basalt plugin add does for an agent: the copy, the entry, the
	// approval through the engine's own derivation.
	p := f.installApproval(feedHooks, "product_a")
	f.writeConfig()
	v, err := Verify(f.root, p.Key(), p.ManifestSHA256, f.trust, pluginmodel.ModeSameUser, RequireApproval(true))
	require.NoError(t, err)
	a := l.open(t, "product_a", PluginApprovalDetail(p.Key(), v, []string{l.roles["product_a"]}), p.ApprovalSettings())
	require.Eventually(t, func() bool {
		probs := ep.pluginProblems("product_a")
		return len(probs) == 1 && probs[0].Code == ProblemPluginAwaitingApproval
	}, 10*time.Second, 50*time.Millisecond, "the engine sees the new entry and waits for its approval")
	require.Empty(t, servedTo(ep, p.Key()))

	l.sign(t, l.person(t), "product_a", a)
	signed := time.Now()
	require.Eventually(t, func() bool {
		return ep.host.State(p.Key()) == StateReady && slices.Equal(servedTo(ep, p.Key()), []string{"product_a"})
	}, 10*time.Second, 20*time.Millisecond, "served without a restart")
	require.Less(t, time.Since(signed), 5*time.Second)
	require.Empty(t, ep.pluginProblems("product_a"))
	require.NoError(t, ep.host.Call(context.Background(), p.Key(), []string{"product_a"}, "feed.observe", nil, nil))
	kinds := kindsOf(l.events(t, "product_a"))
	require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING", "PLUGIN_APPROVED", "PLUGIN_ENABLED"}, kinds)
	require.Len(t, f.reported(".start"), 1, "one process")
}

// Turning an entry off stops it within one tick, without a restart, for an
// entry that requires approval and for one a person added at a terminal;
// the ledger then records it disabled, after it stopped.
func TestDisableStopsWithoutRestart(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	approved := f.installApproval(feedHooks, "product_a")
	signed := f.install("client_x", dial.TransportStdio, "client_x")
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), approved, "product_a")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(approved.Key(), "product_a")
	lp.requireServing(signed.Key(), "client_x")
	started, _ := f.startedPIDs()
	require.Len(t, started, 2)

	f.cfg.Plugins[0].Enabled, f.cfg.Plugins[1].Enabled = false, false
	lp.change()
	lp.requireStopped(approved.Key())
	lp.requireStopped(signed.Key())
	_, shutdown := f.startedPIDs()
	require.ElementsMatch(t, started, shutdown, "each process was asked to shut down")
	require.Eventually(t, func() bool { return !alive(started[0]) && !alive(started[1]) }, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "product_a"))
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "client_x"))
	require.Empty(t, lp.ep.pluginProblems("product_a"), "a disabled entry is not a problem")

	// Turned on again by hand: the approval ended, so it stays withheld.
	f.cfg.Plugins[0].Enabled = true
	lp.change()
	require.Empty(t, servedTo(lp.ep, approved.Key()))
	require.Equal(t, ProblemPluginAwaitingApproval, problemFor(t, lp.ep, "product_a").Code)
}

func lastKind(t *testing.T, l pluginLedgers, agentName string) string {
	t.Helper()
	rows := l.events(t, agentName)
	require.NotEmpty(t, rows)
	return rows[len(rows)-1].Kind
}

// Removing an entry, or an agent from it, stops it without a restart: the
// removed agent is no longer served, and the others are.
func TestRemoveStopsWithoutRestart(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), p, "product_a", "client_x")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "client_x", "product_a")

	f.cfg.Plugins[0].Agents = []string{"product_a"}
	lp.change()
	lp.requireServing(p.Key(), "product_a")
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "client_x"))
	require.Equal(t, "PLUGIN_ENABLED", lastKind(t, l, "product_a"))

	f.cfg.Plugins = nil
	lp.change()
	lp.requireStopped(p.Key())
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "product_a"))
	require.Empty(t, lp.ep.pluginProblems("product_a"))
	require.Empty(t, lp.ep.pluginProblems("client_x"))
}

// A changed entry (a new copy, opened as a new approval by add) stops the
// running plugin as soon as the engine sees the change, is withheld while
// its approval waits, and runs the new copy once that approval is signed:
// the old copy never serves under the new config, the new one never before
// its signature.
func TestChangedEntryRunsOnceItsApprovalIsSigned(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "product_a")
	old, _ := f.startedPIDs()

	// basalt plugin add with a new copy: the copy, the entry, the approval.
	next := f.installCopy("default", detectHooks, false)
	f.cfg.Plugins[0].ManifestSHA256 = next.ManifestSHA256
	lp.change()
	lp.requireStopped(p.Key())
	require.Equal(t, ProblemPluginApprovalMismatch, problemFor(t, lp.ep, "product_a").Code)
	v, err := Verify(f.root, p.Key(), next.ManifestSHA256, f.trust, pluginmodel.ModeSameUser, RequireApproval(true))
	require.NoError(t, err)
	a := l.open(t, "product_a", PluginApprovalDetail(p.Key(), v, []string{l.roles["product_a"]}), f.cfg.Plugins[0].ApprovalSettings())
	lp.poll()
	require.Empty(t, servedTo(lp.ep, p.Key()), "withheld while the new approval waits")
	require.Equal(t, ProblemPluginAwaitingApproval, problemFor(t, lp.ep, "product_a").Code)

	l.sign(t, pk, "product_a", a)
	lp.poll()
	lp.requireServing(p.Key(), "product_a")
	started, _ := f.startedPIDs()
	require.Len(t, started, 2, "a new process for the new copy")
	require.False(t, alive(old[0]))
	rows := l.events(t, "product_a")
	var d guardmodel.PluginDetail
	require.NoError(t, json.Unmarshal([]byte(rows[len(rows)-1].Detail), &d))
	require.Equal(t, "PLUGIN_ENABLED", rows[len(rows)-1].Kind)
	require.Equal(t, next.ManifestSHA256, d.ManifestSHA256)
	require.Equal(t, []string{"wire.detect"}, d.Hooks)
}

// A mismatch found while the plugin runs stops it for that agent: settings
// edited in engine.json without a new approval, and a newer signed approval
// naming the agent that does not match the installed copy. The other agent
// keeps it.
func TestMismatchWhileRunningStopsPlugin(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a")
	l.approve(t, pk, p, "client_x")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "client_x", "product_a")

	// A newer approval for product_a, signed, for another version.
	d := honestDetail(p, l.roles["product_a"])
	d.Version = "9.9.9"
	l.sign(t, pk, "product_a", l.open(t, "product_a", d, p.ApprovalSettings()))
	lp.poll()
	lp.requireServing(p.Key(), "client_x")
	prob := problemFor(t, lp.ep, "product_a")
	require.Equal(t, ProblemPluginApprovalMismatch, prob.Code)
	require.Contains(t, prob.Message, "version")
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "product_a"))

	// Settings edited by hand: the agents' approvals no longer match.
	mc := 0.5
	f.cfg.Plugins[0].MinConfidence = &mc
	lp.change()
	lp.requireStopped(p.Key())
	require.Equal(t, ProblemPluginApprovalMismatch, problemFor(t, lp.ep, "client_x").Code)
	require.Contains(t, problemFor(t, lp.ep, "client_x").Message, "settingsSha256")
}

// engine.json that does not parse, or parses and breaks a rule, changes
// nothing that runs: the plugin keeps serving, status shows
// PLUGIN_CONFIG_INVALID to every agent, and once the file can be read its
// state applies. Two changes in one tick end in the state of the last.
func TestBadConfigWhileRunningChangesNothing(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), p, "product_a")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "product_a")
	started, _ := f.startedPIDs()
	events := len(l.events(t, "product_a"))

	good, err := os.ReadFile(f.configPath)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(good, &m))
	m["plugins"].([]any)[0].(map[string]any)["approval"] = "MAYBE"
	invalid, err := json.Marshal(m)
	require.NoError(t, err)
	for _, bad := range [][]byte{
		good[:len(good)/2], // half written
		[]byte(`{"plugins": "not a list"}`),
		invalid, // parses, and breaks a rule
	} {
		require.NoError(t, os.WriteFile(f.configPath, bad, 0o600))
		lp.w.step(lp.ctx)
		lp.poll()
		lp.requireServing(p.Key(), "product_a")
		for _, a := range []string{"product_a", "client_x"} {
			probs := lp.ep.pluginProblems(a)
			require.Len(t, probs, 1, a)
			require.Equal(t, ProblemPluginConfigInvalid, probs[0].Code)
			require.Empty(t, probs[0].Name)
		}
	}
	require.NoError(t, os.Remove(f.configPath))
	lp.w.step(lp.ctx)
	lp.requireServing(p.Key(), "product_a")
	require.Equal(t, ProblemPluginConfigInvalid, lp.ep.pluginProblems("product_a")[0].Code)
	now, _ := f.startedPIDs()
	require.Equal(t, started, now, "the plugin was never restarted")
	require.Len(t, l.events(t, "product_a"), events, "nothing recorded")

	// Turned off, then on again as it was, before the engine reads the
	// file: the last state, the plugin running, is kept.
	f.cfg.Plugins[0].Enabled = false
	f.writeConfig()
	f.cfg.Plugins[0].Enabled = true
	lp.change()
	lp.requireServing(p.Key(), "product_a")
	require.Empty(t, lp.ep.pluginProblems("product_a"))
	now, _ = f.startedPIDs()
	require.Equal(t, started, now)

	// On, then off: off.
	f.writeConfig()
	f.cfg.Plugins[0].Enabled = false
	lp.change()
	lp.requireStopped(p.Key())
}

// An agent whose database does not answer is checked again after 2, 4,
// 8 ... seconds, up to a minute, not on every tick, and a plugin it runs
// keeps running meanwhile: the approval was verified, and only a check
// that can read the approvals changes it. The other agent is checked as
// usual. Once the database answers, the backoff ends.
func TestWatchBacksOffWhenDatabaseDown(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a", "client_x")
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "client_x", "product_a")

	clock := time.Now()
	lp.w.now = func() time.Time { return clock }
	up := lp.ledgers["product_a"]
	tries := 0
	lp.w.ledgers["product_a"] = AgentLedger{ports: testPorts, db: up.db, admit: func(context.Context) error {
		tries++
		return action.Unavailable(errors.New("connection refused"))
	}}
	var at []int
	for s := range 200 {
		before := tries
		lp.w.next = clock // the agents are due on every tick
		lp.w.step(lp.ctx)
		if tries > before {
			at = append(at, s)
		}
		clock = clock.Add(time.Second)
	}
	require.Equal(t, []int{0, 2, 6, 14, 30, 62, 122, 182}, at, "2, 4, 8, 16, 32, then 60 s apart")
	lp.requireServing(p.Key(), "client_x", "product_a")

	lp.w.ledgers["product_a"] = up
	lp.w.next = clock
	clock = clock.Add(time.Minute)
	lp.w.step(lp.ctx)
	require.NotContains(t, lp.w.backoff, "product_a")
	lp.requireServing(p.Key(), "client_x", "product_a")

	// An answer decides: an agent the engine no longer admits (its guard
	// gone or too old, a setup pending) is withheld, as at start.
	lp.w.ledgers["product_a"] = AgentLedger{ports: testPorts, db: up.db, admit: func(context.Context) error {
		return fmt.Errorf("%w: the guard is not installed", ErrNotAdmitted)
	}}
	lp.w.next = clock
	lp.w.step(lp.ctx)
	lp.requireServing(p.Key(), "client_x")
	require.Contains(t, lp.w.backoff, "product_a", "and checked again after a backoff")
}

// Fifty rounds of add, approve and remove, each started and stopped by the
// watch, leave no goroutine, plugin process, run record or socket
// directory behind. Not parallel: it counts the process's goroutines.
func TestAddApproveRemoveLeavesNothing(t *testing.T) {
	f := newPluginFixture(t)
	p := f.installCopyOver("default", feedHooks, dial.TransportUnix, false)
	p.Agents, p.Approval = []string{"product_a"}, config.PluginApprovalRequired
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	runs := &child.Runs{Dir: filepath.Join(t.TempDir(), "plugin-runs")}
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{Runs: runs}})

	round := func() {
		f.cfg.Plugins = []config.Plugin{p}
		l.approve(t, pk, p, "product_a")
		lp.change()
		lp.requireServing(p.Key(), "product_a")
		recs, err := os.ReadDir(runs.Dir)
		require.NoError(t, err)
		require.Len(t, recs, 1, "the running plugin is recorded")
		f.cfg.Plugins = nil
		lp.change()
		lp.requireStopped(p.Key())
	}
	round()
	base := runtime.NumGoroutine()
	for range 49 {
		round()
	}
	started, _ := f.startedPIDs()
	// At least one process per round; a slow start on a loaded machine may
	// be retried by the supervisor, which must leave nothing behind either.
	require.GreaterOrEqual(t, len(started), 50)
	require.Eventually(t, func() bool {
		return !slices.ContainsFunc(started, alive)
	}, 10*time.Second, 50*time.Millisecond, "every plugin process exited")
	recs, err := os.ReadDir(runs.Dir)
	require.NoError(t, err)
	require.Empty(t, recs, "no run record left")
	dirs, err := os.ReadDir(f.sockBase)
	require.NoError(t, err)
	require.Empty(t, dirs, "no socket directory left")
	// Counted here, not in require.Eventually, which runs its condition on
	// goroutines of its own.
	n := runtime.NumGoroutine()
	for deadline := time.Now().Add(10 * time.Second); n > base && time.Now().Before(deadline); n = runtime.NumGoroutine() {
		time.Sleep(50 * time.Millisecond)
	}
	require.LessOrEqual(t, n, base, "goroutines after 50 rounds, against after the first")
	lp.stop()
	require.Empty(t, lp.ep.sup.Supervised())
}

// An entry that does not require approval, turned off while its agent's
// database does not answer, stops at once; its PLUGIN_DISABLED is written
// once the database answers again, with no further change to engine.json.
// An error that is not the database failing to answer (a reply that does
// not decode) decides: the agent is not kept.
func TestDisableRecordedOnceDatabaseAnswers(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	lp := f.live(l, Options{Ports: testPorts, Dialer: dial.Dialer{}})
	lp.requireServing(p.Key(), "product_a")
	clock := time.Now()
	lp.w.now = func() time.Time { return clock }
	up := lp.ledgers["product_a"]
	down := true
	lp.w.ledgers["product_a"] = AgentLedger{ports: testPorts, db: up.db, admit: func(context.Context) error {
		if down {
			return action.Unavailable(errors.New("connection refused"))
		}
		return nil
	}}

	f.cfg.Plugins[0].Enabled = false
	lp.change()
	lp.requireStopped(p.Key())
	require.Equal(t, "PLUGIN_ENABLED", lastKind(t, l, "product_a"), "not written while the database does not answer")
	require.False(t, lp.w.next.IsZero(), "checked again after the backoff")

	down = false
	for range 5 {
		clock = clock.Add(time.Second)
		lp.w.step(lp.ctx)
	}
	require.Equal(t, "PLUGIN_DISABLED", lastKind(t, l, "product_a"))
	require.Empty(t, lp.w.backoff)
	require.True(t, lp.w.next.IsZero(), "nothing left to check")

	require.False(t, transientErr(errors.New("cannot decode the plugin approval detail")))
	require.True(t, transientErr(action.Unavailable(errors.New("connection refused"))))
	require.True(t, transientErr(context.DeadlineExceeded))
}
