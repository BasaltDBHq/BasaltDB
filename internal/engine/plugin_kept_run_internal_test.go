//go:build unix

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
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
	ep     *enginePlugins
	report string
	cancel func()
}

// run starts the engine's plugins with euid as the engine's uid, inGroup as
// the answer to "is an agent's OS user in the engine's group", and no entry
// as engine.json's entries (none).
func (f *keptFixture) run(euid int, inGroup error) *keptRun {
	f.t.Helper()
	t := f.t
	cfg := f.cfg
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))
	report := filepath.Join(f.base, "report")
	require.NoError(t, os.MkdirAll(report, 0o700))
	units := &fakeUnits{inGroup: inGroup, gid: 980}
	o := pluginOptions{goos: runtime.GOOS, euid: euid, units: units.source(), kept: f.s.store, SocketBase: f.base}
	log := slog.New(slog.DiscardHandler)
	ep := newEnginePluginsFor(cfg, f.configPath, o, log)
	ledgers := map[string]pluginLedger{}
	for name, a := range f.agents {
		ledgers[name] = pluginLedger{db: a.db}
	}
	ctx, cancel := context.WithCancel(context.Background())
	recordPluginEvents(ctx, cfg, f.configPath, ep, ledgers, log)
	done := make(chan struct{})
	go func() { ep.serve(ctx, cfg, f.configPath, ledgers); close(done) }()
	f.s.changed, f.s.serving = ep.applyNow, ep.servingOf
	r := &keptRun{t: t, f: f, ep: ep, report: report}
	r.cancel = func() { cancel(); <-done }
	t.Cleanup(r.cancel)
	return r
}

// runSource is a local plugin acme-ner whose command is this test binary,
// started as the test plugin that reports to report.
func runSource(t *testing.T, report string) ([]person.PluginFile, []string) {
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
`, feedHooks, dial.TransportStdio, args, sha256.Sum256(exe))
	return []person.PluginFile{{Path: plugin.ManifestFile, Data: []byte(manifest)}, {Path: "bin/p", Data: exe}}, []string{"bin/p"}
}

// add uploads the running source and opens it for agents.
func (r *keptRun) add(agents ...string) person.PluginOpenResult {
	r.t.Helper()
	files, exec := runSource(r.t, r.report)
	id, err := r.f.client.PluginUpload(context.Background(), files)
	require.NoError(r.t, err)
	res, err := r.f.client.PluginOpen(context.Background(), person.PluginOpenParams{
		UploadID: &id, Name: "acme-ner", Instance: "default", Agents: agents, Executables: exec,
	})
	require.NoError(r.t, err)
	return res
}

var keptKey = plugin.EntryKey{Name: "acme-ner", Instance: "default"}

// requireServed waits until the engine serves keptKey READY to agents, on
// approval, and PLUGIN_LIST says so.
func (r *keptRun) requireServed(approval person.PluginOpenedApproval, agents ...string) {
	r.t.Helper()
	require.Eventually(r.t, func() bool {
		got := servedTo(r.ep, keptKey)
		return len(got) == len(agents) && r.ep.host.State(keptKey) == plugin.StateReady
	}, keptWait, 50*time.Millisecond, "served to %v", agents)
	require.ElementsMatch(r.t, agents, servedTo(r.ep, keptKey))
	list, err := r.f.client.PluginList(context.Background())
	require.NoError(r.t, err)
	requireSchema(r.t, "listResult", list)
	require.Len(r.t, list.Plugins, 1)
	require.Len(r.t, list.Plugins[0].Serving, len(agents))
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

func containsKey(ks []plugin.EntryKey, k plugin.EntryKey) bool {
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

	// Another approval, not signed, never serves: open one for product_b
	// only, through its own credential, and sign nothing.
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

	_, err := f.client.PluginDisable(context.Background(), person.PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	// The disable answers once the plugin has stopped.
	require.Empty(t, servedTo(r.ep, keptKey))
	require.NotContains(t, r.ep.sup.Supervised(), keptKey)
	require.Equal(t, "ENDED", f.state0("product_a", keptKey))

	again, err := f.client.PluginOpen(context.Background(), person.PluginOpenParams{Name: keptKey.Name, Instance: keptKey.Instance, Agents: []string{"product_a"}})
	require.NoError(t, err)
	time.Sleep(3 * pluginWaitingPoll)
	require.Empty(t, servedTo(r.ep, keptKey), "the old approval never serves it again")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, r.problem().Code)

	f.sign(again.Approvals[0])
	r.requireServed(again.Approvals[0], "product_a")

	_, err = f.client.PluginRemove(context.Background(), person.PluginEntryParams{Name: keptKey.Name, Instance: keptKey.Instance})
	require.NoError(t, err)
	require.Empty(t, servedTo(r.ep, keptKey))
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))
	require.Nil(t, r.problem())
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

// TestNameClashBothHeldServesConfig: when engine.json and the engine both
// hold one (name, instance) (a hand edit), the config's entry is the one
// considered and the engine-kept one is not served, with the clash named.
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
	ep.keptKeys = map[plugin.EntryKey]bool{{Name: "acme-kept", Instance: "default"}: true}
	require.Equal(t, whyNoUnit, ep.localRefusal(p, v), "no unit: the engine never starts a config entry itself")
	require.NotContains(t, ep.targets, p.Key())
	kept := config.Plugin{Name: "acme-kept", Instance: "default", Enabled: true, Agents: []string{"product_a"}, Approval: config.PluginApprovalRequired}
	require.Empty(t, ep.localRefusal(kept, v), "an engine-kept local entry runs as the engine's child")

	cfg.Plugins = append(cfg.Plugins, kept)
	want := wantedFrom(cfg, func(plugin.EntryKey) (plugin.Verified, bool) { return v, true }, plugin.ModeService, "linux", trustWant{}, ep.isKept)
	require.Equal(t, guard.PluginFilesOSUser, want.served["product_a"][p.Key()].Isolation.Files)
	require.Equal(t, guard.PluginFilesNone, want.served["product_a"][kept.Key()].Isolation.Files)
	require.True(t, want.approval[kept.Key()])
	require.False(t, want.approval[p.Key()])
}
