//go:build unix

package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// keptWait bounds a wait on the running engine: a cold start of the test
// binary as a plugin under -race is slow.
const keptWait = 60 * time.Second

// keptRun is a service engine running f's engine-kept entries (and cfg's
// config entries) as RunWith does: recorded, started and watched, with
// the person socket's changes applied before they answer.
type keptRun struct {
	t      *testing.T
	f      *keptFixture
	ep     *Plugins
	report string
	cancel func()
}

// run starts the engine's plugins with euid as the engine's uid, inGroup as
// the answer to "is an agent's OS user in the engine's group", and no entry
// as engine.json's entries (none).
func (f *keptFixture) run(euid int, inGroup error) *keptRun {
	f.t.Helper()
	return f.runWith(euid, inGroup, nil)
}

// runWith is run with the engine's plugin options changed by set (nil
// changes nothing).
func (f *keptFixture) runWith(euid int, inGroup error, set func(*Options)) *keptRun {
	f.t.Helper()
	t := f.t
	cfg := f.cfg
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))
	report := filepath.Join(f.base, "report")
	require.NoError(t, os.MkdirAll(report, 0o700))
	units := &fakeUnits{inGroup: inGroup, gid: 980}
	o := Options{Ports: testPorts, Dialer: dial.Dialer{}, goos: runtime.GOOS, euid: euid, units: units.source(), kept: f.s.store, SocketBase: f.base}
	if set != nil {
		set(&o)
	}
	log := slog.New(slog.DiscardHandler)
	ep := NewFor(cfg, f.configPath, o, log)
	ledgers := map[string]AgentLedger{}
	for name, a := range f.agents {
		ledgers[name] = AgentLedger{ports: testPorts, db: a.db}
	}
	ctx, cancel := context.WithCancel(context.Background())
	RecordEvents(ctx, cfg, f.configPath, ep, ledgers, log)
	done := make(chan struct{})
	go func() { ep.Serve(ctx, cfg, f.configPath, ledgers); close(done) }()
	f.s.changed, f.s.serving, f.s.health = ep.applyNow, ep.servingOf, ep.healthOf
	r := &keptRun{t: t, f: f, ep: ep, report: report}
	r.cancel = func() { cancel(); <-done }
	t.Cleanup(r.cancel)
	return r
}

// runSource is a local plugin acme-ner whose command is this test binary,
// started as the test plugin that reports to report.
func runSource(t *testing.T, report, hooks string) ([]shimFile, []string) {
	t.Helper()
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	args, err := json.Marshal([]string{testPluginFlag, "report=" + report})
	require.NoError(t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": "1.4.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": %s,
  "endpoint": { "local": { "transport": %q, "command": "bin/p", "args": %s } },
  "files": { "bin/p": "sha256:%x" },
  "network": { "egress": [] }
}
`, hooks, dial.TransportStdio, args, sha256.Sum256(exe))
	return []shimFile{{Path: ManifestFile, Data: []byte(manifest)}, {Path: "bin/p", Data: exe}}, []string{"bin/p"}
}

// add uploads the running source and opens it for agents.
func (r *keptRun) add(agents ...string) PluginOpenResult {
	r.t.Helper()
	return r.addWith(feedHooks, agents...)
}

// addWith is add for a plugin that declares hooks.
func (r *keptRun) addWith(hooks string, agents ...string) PluginOpenResult {
	r.t.Helper()
	files, exec := runSource(r.t, r.report, hooks)
	id, err := r.f.client.PluginUpload(context.Background(), files)
	require.NoError(r.t, err)
	res, err := r.f.client.PluginOpen(context.Background(), PluginOpenParams{
		UploadID: &id, Name: "acme-ner", Instance: "default", Agents: agents, Executables: exec,
	})
	require.NoError(r.t, err)
	return res
}

var keptKey = pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}

// requireServed waits until the engine serves keptKey READY to agents, on
// approval, and PLUGIN_LIST says so.
func (r *keptRun) requireServed(approval PluginOpenedApproval, agents ...string) {
	r.t.Helper()
	require.Eventually(r.t, func() bool {
		got := servedTo(r.ep, keptKey)
		return len(got) == len(agents) && r.ep.host.State(keptKey) == StateReady
	}, keptWait, 50*time.Millisecond, "served to %v", agents)
	require.ElementsMatch(r.t, agents, servedTo(r.ep, keptKey))
	list, err := r.f.client.PluginList(context.Background())
	require.NoError(r.t, err)
	requireSchema(r.t, "listResult", list)
	require.Len(r.t, list.Plugins, 1)
	require.Len(r.t, list.Plugins[0].Serving, len(agents))
	require.Equal(r.t, HealthReady, list.Plugins[0].Health, "the engine started it and it answers")
	for _, sv := range list.Plugins[0].Serving {
		require.Equal(r.t, *approval.ApprovalID, *sv.ApprovalID)
	}
}

// requireNotRunning: keptKey runs for no agent and is supervised by nobody.
func (r *keptRun) requireNotRunning() {
	r.t.Helper()
	require.Eventually(r.t, func() bool {
		return len(servedTo(r.ep, keptKey)) == 0 && !containsKey(r.ep.sup.Supervised(), keptKey)
	}, keptWait, 50*time.Millisecond)
}

func containsKey(ks []pluginmodel.EntryKey, k pluginmodel.EntryKey) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

// problem is product_a's status problem for keptKey, nil when there is
// none.
func (r *keptRun) problem() *agent.PluginProblem {
	for _, p := range r.ep.PluginProblems("product_a") {
		if p.Name == keptKey.Name && p.Instance == keptKey.Instance {
			return &p
		}
	}
	return nil
}

// TestEngineKeptEntryNeedsApproval: an engine-kept entry is served only on
// a matching signed approval, as the engine's own child, recorded with
// files NONE; a change that does not match withholds it again.
func TestEngineKeptEntryNeedsApproval(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a", "product_b"})
	r := f.run(os.Geteuid(), nil)
	res := r.add("product_a", "product_b")
	a := res.Approvals[0]

	r.requireNotRunning()
	require.Eventually(t, func() bool {
		p := r.problem()
		return p != nil && p.Code == agent.ProblemPluginAwaitingApproval
	}, keptWait, 50*time.Millisecond)

	f.sign(a)
	r.requireServed(a, "product_a", "product_b")
	require.Nil(t, r.problem())
	var detail map[string]any
	require.NoError(t, f.d.Admin.QueryRow(context.Background(), `SELECT detail FROM basalt_meta.ledger
		WHERE agent = $1 AND kind = 'PLUGIN_ENABLED' ORDER BY seq DESC LIMIT 1`, f.roles["product_a"].Role).Scan(&detail))
	require.Equal(t, map[string]any{"files": "NONE", "network": "NOT_ENFORCED"}, detail["isolation"])
	require.Equal(t, "UNKNOWN", detail["signer"])

	// The engine's user edits the settings behind the engine's back: the
	// approval no longer matches, and the entry stops.
	timeout := 2000
	require.NoError(t, f.s.store.Update(f.cfg, func(es []config.Plugin) ([]config.Plugin, error) {
		es[0].TimeoutMs = timeout
		return es, nil
	}))
	r.ep.applyNow(context.Background())
	r.requireNotRunning()
	require.Eventually(t, func() bool {
		p := r.problem()
		return p != nil && p.Code == agent.ProblemPluginApprovalMismatch
	}, keptWait, 50*time.Millisecond)
	require.True(t, r.problem().EngineKept, "its status steps name no sudo and no check")
}

// TestServiceModeStartsWithoutRestart: the engine starts an engine-kept
// entry within seconds of the signature, stops it on disable, needs a new
// signature after an enable, and stops and deletes it on remove, never
// restarted.
func TestServiceModeStartsWithoutRestart(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	r := f.run(os.Geteuid(), nil)
	res := r.add("product_a")
	f.sign(res.Approvals[0])
	r.requireServed(res.Approvals[0], "product_a")
	starts := len(reportedFiles(t, r.report, ".start"))
	require.Positive(t, starts)

	_, err := f.client.PluginDisable(context.Background(), PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	// The disable answers once the plugin has stopped.
	require.Empty(t, servedTo(r.ep, keptKey))
	require.NotContains(t, r.ep.sup.Supervised(), keptKey)
	require.Equal(t, "ENDED", f.state0("product_a", keptKey))

	again, err := f.client.PluginOpen(context.Background(), PluginOpenParams{Name: keptKey.Name, Instance: keptKey.Instance, Agents: []string{"product_a"}})
	require.NoError(t, err)
	time.Sleep(3 * pluginWaitingPoll)
	require.Empty(t, servedTo(r.ep, keptKey), "the old approval never serves it again")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, r.problem().Code)

	f.sign(again.Approvals[0])
	r.requireServed(again.Approvals[0], "product_a")

	_, err = f.client.PluginRemove(context.Background(), PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	require.Empty(t, servedTo(r.ep, keptKey))
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))
	require.Nil(t, r.problem())
}

// TestFeedFollowsEngineKeptEntries: the notifier hooks follow an entry a
// service engine keeps itself, which it starts while it runs and not from
// engine.json: the entry gets a sender and its agent's ledger events once
// it is served, and loses the sender when it is turned off.
func TestFeedFollowsEngineKeptEntries(t *testing.T) {
	f := newKeptFixture(t, []string{"product_b"})
	timing := fastFeed
	r := f.runWith(os.Geteuid(), nil, func(o *Options) { o.stateDir, o.feedTiming = f.state, &timing })
	res := r.add("product_b")
	require.Never(t, func() bool { return r.ep.senders.sender(keptKey) != nil }, 10*timing.follow, timing.follow,
		"no sender before the entry is approved")

	f.sign(res.Approvals[0])
	r.requireServed(res.Approvals[0], "product_b")
	require.Eventually(t, func() bool { return r.ep.senders.sender(keptKey) != nil }, keptWait, 20*time.Millisecond,
		"the engine-kept entry's sender, for the notifier hooks")

	fe := &feedEnv{
		t: t, stateDir: f.state,
		l: pluginLedgers{d: f.d, roles: map[string]string{"product_b": f.roles["product_b"].Role}},
	}
	fe.started(keptKey, "product_b")
	seq := fe.applied("product_b")
	fed := &pluginFixture{t: t, report: r.report}
	sch := feedSchema(t)
	require.Eventually(t, func() bool { return slices.Contains(fed.fedSeqs(sch, "product_b"), seq) }, keptWait, 20*time.Millisecond,
		"the agent's ledger events reach the engine-kept entry")

	_, err := f.client.PluginDisable(context.Background(), PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	require.Empty(t, servedTo(r.ep, keptKey))
	require.Eventually(t, func() bool { return r.ep.senders.sender(keptKey) == nil }, keptWait, 20*time.Millisecond,
		"its sender stops with it")
}

// TestDeliveryReachesEngineKeptEntries: approval.deliver follows an entry a
// service engine keeps itself. Once it is approved and served, a notice of
// its agent reaches the plugin process, as the contract's event with the
// agent's link; a notice of an agent it does not serve reaches nothing;
// after it is turned off nothing more is sent and nothing is counted.
func TestDeliveryReachesEngineKeptEntries(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a", "product_b"})
	timing, tries := fastFeed, fastDeliver
	r := f.runWith(os.Geteuid(), nil, func(o *Options) { o.stateDir, o.feedTiming, o.deliverTiming = f.state, &timing, &tries })
	res := r.addWith(notifyHooks, "product_b")
	notice := agent.LinkNotice{
		Kind: agent.NoticeApprovalRequested, ApprovalID: uuid.MustParse(testApproval), Headline: "Update 27 rows in public·leads",
		ExpiresAt: time.Now().Add(time.Hour), Link: localShort,
	}
	// Not approved yet: not served, so nothing is sent or counted.
	r.ep.DeliverLinks("product_b").DeliverLink(notice)

	f.sign(res.Approvals[0])
	r.requireServed(res.Approvals[0], "product_b")
	require.Eventually(t, func() bool { return r.ep.senders.sender(keptKey) != nil }, keptWait, 20*time.Millisecond)
	r.ep.DeliverLinks("product_a").DeliverLink(notice)
	r.ep.DeliverLinks("product_b").DeliverLink(notice)

	sch := deliverSchema(t)
	var got []gotNotice
	require.Eventually(t, func() bool {
		got = reportedNotices(t, r.report, sch)
		return len(got) > 0
	}, keptWait, 20*time.Millisecond, "the notice reaches the engine-kept entry")
	time.Sleep(3 * fastDeliver.tries[3])
	got = reportedNotices(t, r.report, sch)
	require.Len(t, got, 1, "one notice: nothing from before the approval, nothing of product_a")
	require.Equal(t, "product_b", got[0].Agent)
	require.Equal(t, localShort, got[0].Event.Data["link"])
	install, err := guard.InstallID(context.Background(), f.d.Admin)
	require.NoError(t, err)
	require.Equal(t, "urn:uuid:"+install.String(), got[0].Event.Source, "the install id, read through the agent's own connection")
	require.NotContains(t, string(got[0].raw), "product_a")

	_, err = f.client.PluginDisable(context.Background(), PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	r.ep.DeliverLinks("product_b").DeliverLink(notice)
	time.Sleep(3 * fastDeliver.tries[3])
	require.Len(t, reportedNotices(t, r.report, sch), 1, "turned off: nothing more")
	for _, a := range []string{"product_a", "product_b"} {
		require.Empty(t, r.ep.delivery.dropped(a), "a notice for an entry not served is not a dropped one")
	}
}

// reportedNotices are the approval.deliver requests the test plugin
// processes kept in dir, each checked against deliver.schema.json.
func reportedNotices(t *testing.T, dir string, sch *jsonschema.Schema) []gotNotice {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.deliver"))
	require.NoError(t, err)
	var out []gotNotice
	for _, name := range files {
		raw, err := os.ReadFile(name)
		require.NoError(t, err)
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
			var req struct {
				Params json.RawMessage `json:"params"`
			}
			if json.Unmarshal(line, &req) != nil {
				continue // a line still being written
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(req.Params))
			require.NoError(t, err)
			require.NoError(t, sch.Validate(inst), string(req.Params))
			g := gotNotice{raw: req.Params}
			require.NoError(t, json.Unmarshal(req.Params, &g))
			out = append(out, g)
		}
	}
	return out
}

func reportedFiles(t *testing.T, dir, suffix string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	require.NoError(t, err)
	var out []string
	for _, de := range des {
		if filepath.Ext(de.Name()) == suffix {
			out = append(out, de.Name())
		}
	}
	return out
}

// TestRootEngineStartsNoLocalPlugin: an engine running as root starts no
// engine-kept local plugin, approved or not.
func TestRootEngineStartsNoLocalPlugin(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	r := f.run(0, nil)
	res := r.add("product_a")
	f.sign(res.Approvals[0])
	require.Eventually(t, func() bool {
		p := r.problem()
		return p != nil && p.Code == agent.ProblemPluginUnavailable
	}, keptWait, 50*time.Millisecond)
	require.Contains(t, r.problem().Message, "root")
	time.Sleep(3 * pluginWaitingPoll)
	require.Empty(t, servedTo(r.ep, keptKey))
	require.Empty(t, reportedFiles(t, r.report, ".start"), "no plugin process ever started")
}

// TestEngineKeptLocalRefusedWhenAgentInEngineGroup: an agent's OS user in
// the engine's group stops every engine-kept local entry from starting.
func TestEngineKeptLocalRefusedWhenAgentInEngineGroup(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	r := f.run(os.Geteuid(), errors.New("product_a's OS user is in the engine's group"))
	res := r.add("product_a")
	f.sign(res.Approvals[0])
	require.Eventually(t, func() bool {
		p := r.problem()
		return p != nil && p.Code == agent.ProblemPluginUnavailable
	}, keptWait, 50*time.Millisecond)
	time.Sleep(3 * pluginWaitingPoll)
	require.Empty(t, reportedFiles(t, r.report, ".start"))
}

// TestNameClashBothHeldServesConfig: when engine.json comes to hold the
// (name, instance) of a running engine-kept entry (a hand edit), the
// engine-kept one stops and is not served, with the clash named; the
// config's entry takes effect at the next start, as every config entry.
func TestNameClashBothHeldServesConfig(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	r := f.run(os.Geteuid(), nil)
	res := r.add("product_a")
	f.sign(res.Approvals[0])
	r.requireServed(res.Approvals[0], "product_a")

	held := config.Plugin{Name: "acme-ner", Instance: "default", ManifestSHA256: f.entries()[0].ManifestSHA256, Enabled: true, Agents: []string{"product_a"}}
	cfg := f.cfg
	cfg.Plugins = []config.Plugin{held}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))
	r.ep.applyNow(context.Background())
	r.requireNotRunning()
	require.Eventually(t, func() bool {
		p := r.problem()
		return p != nil && p.Code == agent.ProblemPluginUnavailable
	}, keptWait, 50*time.Millisecond)
	require.Contains(t, r.problem().Message, "engine.json holds an entry of the same name")
	require.True(t, r.problem().EngineKept)
	// The engine-kept entry is not run, and the list says so of it.
	list, err := r.f.client.PluginList(context.Background())
	require.NoError(t, err)
	for _, l := range list.Plugins {
		if l.Source == SourceEngine {
			require.Equal(t, HealthNotStarted, l.Health)
		}
	}
}

// TestSudoInstalledPluginStillIsolated: with engine-kept entries on, a
// config entry (added with sudo) is still reached only through its own
// unit, never started by the engine, and recorded files OS_USER; only an
// engine-kept entry runs as the engine's child, recorded files NONE.
func TestSudoInstalledPluginStillIsolated(t *testing.T) {
	cfg := svcConfig()
	v := svcVerified()
	p := cfg.Plugins[0]
	ep := serviceEngine(cfg, &fakeUnits{uids: map[string]int{"basalt-plugin-acme-ner-default": 990}}, 995)
	ep.keptKeys = map[pluginmodel.EntryKey]bool{{Name: "acme-kept", Instance: "default"}: true}
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v), "no unit: the engine never starts a config entry itself")
	require.NotContains(t, ep.targets, p.Key())
	kept := config.Plugin{Name: "acme-kept", Instance: "default", Enabled: true, Agents: []string{"product_a"}, Approval: config.PluginApprovalRequired}
	require.Empty(t, ep.localRefusal(kept, v), "an engine-kept local entry runs as the engine's child")

	cfg.Plugins = append(cfg.Plugins, kept)
	want := wantedFrom(cfg, func(pluginmodel.EntryKey) (pluginmodel.Verified, bool) { return v, true }, pluginmodel.ModeService, "linux", testPorts.Network, trustWant{}, ep.isKept)
	require.Equal(t, guardmodel.PluginFilesOSUser, want.served["product_a"][p.Key()].Isolation.Files)
	require.Equal(t, guardmodel.PluginFilesNone, want.served["product_a"][kept.Key()].Isolation.Files)
	require.True(t, want.approval[kept.Key()])
	require.False(t, want.approval[p.Key()])
}

// TestServiceWatchLeavesConfigEntriesAlone: a service engine's watch holds
// its config entries (added with sudo) as the start decided: their ledger
// record is never ended by a pass, and their status is never cleared.
func TestServiceWatchLeavesConfigEntriesAlone(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	sudoKey := pluginmodel.EntryKey{Name: "acme-sudo", Instance: "default"}
	held := config.Plugin{Name: sudoKey.Name, Instance: sudoKey.Instance, ManifestSHA256: strings.Repeat("a", 64), Enabled: true, Agents: []string{"product_a"}}
	db := f.agents["product_a"].db
	recorded := guardmodel.PluginDetail{
		Name: sudoKey.Name, Instance: sudoKey.Instance, Version: "1.0.0", ManifestSHA256: held.ManifestSHA256,
		Hooks: []string{"feed.observe"}, Egress: []string{}, Endpoint: guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointLocal},
		Isolation: &guardmodel.PluginIsolation{Files: guardmodel.PluginFilesOSUser, Network: guardmodel.PluginNetworkEnforced}, Signer: string(pluginmodel.SignerUnknown),
	}
	require.NoError(t, guard.RecordPluginEntryEvent(context.Background(), db, guardmodel.PluginEnabled, recorded))

	start := f.cfg
	start.Plugins = []config.Plugin{held}
	ep := &Plugins{kept: f.s.store, keptKeys: map[pluginmodel.EntryKey]bool{}, mode: pluginmodel.ModeService, o: Options{Ports: testPorts, Dialer: dial.Dialer{}, goos: "linux"}}
	w := &pluginWatch{ep: ep, start: start, eff: start}
	notStarted := func(pluginmodel.EntryKey) (pluginmodel.Verified, bool) { return pluginmodel.Verified{}, false }
	want := w.wanted(notStarted)
	require.True(t, want.frozen[sudoKey])
	pass := writeAgentPluginEvents(context.Background(), "product_a", want, AgentLedger{ports: testPorts, db: db}, slog.New(slog.DiscardHandler))
	require.True(t, pass.reached)
	require.Empty(t, pass.disables, "a pass never ends a config entry's record")

	// Without the hold the same pass would end it: the check is not vacuous.
	want.frozen = nil
	pass = writeAgentPluginEvents(context.Background(), "product_a", want, AgentLedger{ports: testPorts, db: db}, slog.New(slog.DiscardHandler))
	require.NotEmpty(t, pass.disables)

	// A pass keeps a config entry's status and replaces a kept entry's.
	keptKey := pluginmodel.EntryKey{Name: "acme-kept", Instance: "default"}
	ep.unrecorded = map[pluginmodel.EntryKey]map[string]withheldWhy{
		sudoKey: {"product_a": {why: "start"}},
		keptKey: {"product_a": {why: "old"}},
	}
	ep.setWithheldLocked(map[string]agentPass{"product_a": {reached: true}}, nil, w.frozenNow())
	require.Equal(t, "start", ep.unrecorded[sudoKey]["product_a"].why)
	require.Empty(t, ep.unrecorded[keptKey]["product_a"].why)
	require.True(t, w.frozenNow()(sudoKey))
	require.False(t, w.frozenNow()(keptKey))
}

// TestAgentOperatedEngineKeepsPlugins: an agent-operated engine on the
// bot's computer (same-user mode) keeps engine-kept entries, runs one as
// its own child once its approval is signed, with no restart, and stops it
// on remove (CONTRACT.md, Plugin approval through the portal). Its config
// entries are not frozen at start, as a service engine's are: a same-user
// engine applies engine.json while it runs.
func TestAgentOperatedEngineKeepsPlugins(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	f.cfg.Mode, f.cfg.OperatedBy = "", mcpcontract.OperatedByAgent
	f.s.cfg = f.cfg
	r := f.run(os.Geteuid(), nil)
	// engine.json as init writes it on the bot's computer, which the
	// same-user watch reads every second.
	raw, err := json.Marshal(map[string]any{
		"socketDir": f.cfg.SocketDir, "stateDir": f.state, "mode": "SAME_USER", "operatedBy": mcpcontract.OperatedByAgent, "pagesUrl": links.Portal,
		"agents": []map[string]any{{"name": "product_a", "osUser": f.cfg.Agents[0].OSUser, "store": map[string]any{"kind": "POSTGRES", "credentialFile": "/c/product_a"}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(f.configPath, raw))
	_, err = config.Load(f.configPath)
	require.NoError(t, err, "the watch reads engine.json")
	require.Equal(t, pluginmodel.ModeSameUser, r.ep.mode)
	require.NotNil(t, r.ep.kept)
	res := r.add("product_a")
	r.requireNotRunning()
	f.sign(res.Approvals[0])
	r.requireServed(res.Approvals[0], "product_a")
	var detail map[string]any
	require.NoError(t, f.d.Admin.QueryRow(context.Background(), `SELECT detail FROM basalt_meta.ledger
		WHERE agent = $1 AND kind = 'PLUGIN_ENABLED' ORDER BY seq DESC LIMIT 1`, f.roles["product_a"].Role).Scan(&detail))
	require.Equal(t, map[string]any{"files": "NONE", "network": "NOT_ENFORCED"}, detail["isolation"])

	w := &pluginWatch{ep: r.ep, start: f.cfg, eff: f.cfg}
	require.False(t, w.serviceKept())
	require.False(t, w.frozenNow()(pluginmodel.EntryKey{Name: "acme-config", Instance: "default"}), "config entries change while it runs")

	// engine.json that cannot be read holds back hand edits, never a
	// removal: the plugin stops before request_plugin answers REMOVED.
	require.NoError(t, config.WriteFile(f.configPath, []byte("{")))
	r.ep.applyNow(context.Background())
	require.ElementsMatch(t, []string{"product_a"}, servedTo(r.ep, keptKey), "a bad engine.json changes nothing that runs")
	_, err = f.client.PluginRemove(context.Background(), PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	require.Empty(t, servedTo(r.ep, keptKey), "stopped when the removal answers")
	r.requireNotRunning()
}
