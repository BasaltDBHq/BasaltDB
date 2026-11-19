//go:build unix

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
)

// Hooks of the test plugin's manifest.
const (
	feedHooks   = `{ "feed.observe": { "contract": "feed/1" } }`
	detectHooks = `{ "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } }`
)

// installApproval adds an enabled default entry of the test plugin with hooks, for
// agents, that requires approval: no .sig (signer UNKNOWN), installed as
// basalt plugin add does for an approval, with "approval": "REQUIRED".
func (f *pluginFixture) installApproval(hooks string, agents ...string) config.Plugin {
	f.t.Helper()
	p := f.installCopy("default", hooks, false)
	p.Agents, p.Approval = agents, config.PluginApprovalRequired
	f.cfg.Plugins = append(f.cfg.Plugins, p)
	return p
}

// installCopy installs a copy of the test plugin with hooks, signed by a new
// trusted key when signed, else with no .sig, and returns its entry with no
// agents.
func (f *pluginFixture) installCopy(instance, hooks string, signed bool) config.Plugin {
	f.t.Helper()
	return f.installCopyOver(instance, hooks, dial.TransportStdio, signed)
}

// installCopyOver is installCopy over transport.
func (f *pluginFixture) installCopyOver(instance, hooks, transport string, signed bool) config.Plugin {
	f.t.Helper()
	t := f.t
	src := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(src, "bin"), 0o755))
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(src, "bin", "p"), exe, 0o755))
	args, err := json.Marshal([]string{testPluginFlag, "report=" + f.report})
	require.NoError(t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": "1.4.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": %s,
  "endpoint": { "local": { "transport": %q, "command": "bin/p", "args": %s } },
  "files": { "bin/p": "sha256:%x" },
  "network": { "egress": [] }
}
`, hooks, transport, args, sha256.Sum256(exe))
	require.NoError(t, os.WriteFile(filepath.Join(src, plugin.ManifestFile), []byte(manifest), 0o644))
	if signed {
		key, err := plugin.GenerateKey()
		require.NoError(t, err)
		pemBytes, err := plugin.MarshalPublicKey(&key.PublicKey)
		require.NoError(t, err)
		_, _, err = f.trust.Add(pemBytes)
		require.NoError(t, err)
		sig, err := plugin.SignManifest([]byte(manifest), key)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(src, plugin.SignatureFile), sig, 0o644))
	}
	v, err := plugin.Install(src, f.root, instance, f.trust, plugin.ModeSameUser, plugin.RequireApproval(!signed))
	require.NoError(t, err)
	return config.Plugin{Name: "acme-ner", Instance: instance, ManifestSHA256: v.ManifestSHA256, Enabled: true, Agents: []string{}}
}

// honestDetail is what basalt plugin would open for entry p of the test
// plugin with hooks feed.observe in same-user mode, naming roles: written
// out here, not derived by the engine's code.
func honestDetail(p config.Plugin, roles ...string) guard.PluginApprovalDetail {
	return guard.PluginApprovalDetail{
		Agents: roles, Name: "acme-ner", Instance: p.Key().Instance, Version: "1.4.0",
		ManifestSHA256: p.ManifestSHA256, Hooks: []string{"feed.observe"}, Egress: []string{},
		Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
		Signer:    guard.PluginSignerUnknown,
	}
}

// person registers a passkey on the fixture's database, as basalt init
// does.
func (l pluginLedgers) person(t *testing.T) *passkeytest.Authenticator {
	t.Helper()
	return registerPerson(t, l.d)
}

func registerPerson(t *testing.T, d *guardtest.DB) *passkeytest.Authenticator {
	t.Helper()
	p, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, p.Credential(), "app"))
	return p
}

// open opens a plugin approval on opener's connection.
func (l pluginLedgers) open(t *testing.T, opener string, d guard.PluginApprovalDetail, s guard.PluginSettings) guard.PluginApproval {
	t.Helper()
	a, err := guard.OpenPluginApproval(context.Background(), l.dbs[opener].db, d, s)
	require.NoError(t, err)
	return a
}

// sign signs a with the person's passkey and relays it through relay's
// connection.
func (l pluginLedgers) sign(t *testing.T, pk *passkeytest.Authenticator, relay string, a guard.PluginApproval) {
	t.Helper()
	as, err := pk.Sign(approval.Challenge(a.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.SubmitPluginApproval(context.Background(), l.dbs[relay].db, guard.PluginApprovalResponse{ApprovalID: a.ID, Assertion: as})
	require.NoError(t, err)
}

// approve opens and signs an honest approval of p for agents, opened by the
// first of them, with p's settings.
func (l pluginLedgers) approve(t *testing.T, pk *passkeytest.Authenticator, p config.Plugin, agents ...string) {
	t.Helper()
	roles := make([]string, 0, len(agents))
	for _, a := range agents {
		roles = append(roles, l.roles[a])
	}
	l.sign(t, pk, agents[0], l.open(t, agents[0], honestDetail(p, roles...), p.ApprovalSettings()))
}

// servedTo are the agents the host serves entry k to, none when it is not
// started.
func servedTo(ep *enginePlugins, k plugin.EntryKey) []string {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for _, e := range ep.entries {
		if e.Key == k {
			return slices.Sorted(slices.Values(e.Agents))
		}
	}
	return nil
}

// requireNotWithheld: entry k is served to agentName, and status reports
// no approval or record problem for it (the plugin itself is not running
// in these tests, so it is not READY).
func requireNotWithheld(t *testing.T, ep *enginePlugins, k plugin.EntryKey, agentName string) {
	t.Helper()
	require.Contains(t, servedTo(ep, k), agentName)
	require.Empty(t, ep.unrecordedFor(k, agentName), agentName)
	for _, pr := range ep.PluginProblems(agentName) {
		require.Equal(t, agent.ProblemPluginUnavailable, pr.Code, agentName)
		require.Contains(t, pr.Message, "is not ready", agentName)
	}
}

func problemFor(t *testing.T, ep *enginePlugins, agentName string) agent.PluginProblem {
	t.Helper()
	probs := ep.PluginProblems(agentName)
	require.Len(t, probs, 1, "%+v", probs)
	return probs[0]
}

// An entry that requires approval and holds a signed one for each agent that
// matches the installed copy and the settings is served to both, recorded
// with signer UNKNOWN and no key id, with no trust record. The settings are
// hashed as Postgres writes them: config keeps 0.60 and reads 1e3 as 1000.
// The copy, unsigned, verifies again before a restart.
func TestApprovedEntryIsServed(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.installApproval(feedHooks, "product_a", "client_x")
	mc := 0.60
	f.cfg.Plugins[0].Config = json.RawMessage(`{"threshold": 0.60, "max": 1e3, "langs": ["en", "id"]}`)
	f.cfg.Plugins[0].MinConfidence = &mc
	p := f.cfg.Plugins[0]
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), p, "product_a", "client_x")

	ep := f.plugins(nil)
	for range 2 {
		l.record(t, f, ep)
	}
	require.Equal(t, []string{"client_x", "product_a"}, servedTo(ep, p.Key()))
	for _, a := range []string{"product_a", "client_x"} {
		requireNotWithheld(t, ep, p.Key(), a)
		rows := l.events(t, a)
		kinds := kindsOf(rows)
		require.NotContains(t, kinds, "PLUGIN_TRUST_ADDED", a)
		require.Equal(t, "PLUGIN_ENABLED", kinds[len(kinds)-1], a)
		require.Equal(t, 1, slices.Index(kinds, "PLUGIN_ENABLED")-slices.Index(kinds, string(guard.PluginApproved)), "served once, after the approval")
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(rows[len(rows)-1].Detail), &d))
		require.Equal(t, "UNKNOWN", d["signer"], a)
		require.NotContains(t, d, "signerKeyId", a)
	}

	runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	_, err := ep.verified(p.Key())
	require.NoError(t, err, "a restart verifies the unsigned copy as an approved one")
}

// With no approval opened, with one pending and with one cancelled by a
// newer approval that does not name the agent, the entry is withheld from
// the agent with PLUGIN_AWAITING_APPROVAL and nothing is recorded.
func TestUnapprovedEntryIsWithheld(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)

	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	require.Empty(t, ep.entries, "an entry no agent is served is not started")
	prob := problemFor(t, ep, "product_a")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, prob.Code)
	require.Equal(t, "acme-ner", prob.Name)
	require.Equal(t, "default", prob.Instance)
	require.Contains(t, prob.Message, "acme-ner/default")
	require.Contains(t, prob.Message, "no plugin approval names this agent")
	require.Empty(t, l.events(t, "product_a"))

	pending := l.open(t, "product_a", honestDetail(p, l.roles["product_a"]), p.ApprovalSettings())
	ep = f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	prob = problemFor(t, ep, "product_a")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, prob.Code)
	require.Contains(t, prob.Message, "waiting for a person to sign it")
	require.Contains(t, prob.Message, pending.ExpiresAt.UTC().Format("2006-01-02 15:04"), "the pending approval's expiry")

	// client_x opens one naming only itself: product_a's pending one is
	// cancelled, and product_a stays withheld.
	l.open(t, "client_x", honestDetail(p, l.roles["client_x"]), p.ApprovalSettings())
	ep = f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "product_a").Code)
	require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING"}, kindsOf(l.events(t, "product_a")), "nothing recorded as served")
}

// A pending approval that expired unsigned is reported as expired, and the
// entry is never served.
func TestExpiredPendingIsReported(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)
	a := l.open(t, "product_a", honestDetail(p, l.roles["product_a"]), p.ApprovalSettings())
	pk := l.person(t)
	as, err := pk.Sign(approval.Challenge(a.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	l.d.Exec(t, `UPDATE basalt_meta.plugin_approvals SET expires_at = now() - interval '1 second'`)

	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	prob := problemFor(t, ep, "product_a")
	require.Equal(t, agent.ProblemPluginApprovalExpired, prob.Code)
	require.Contains(t, prob.Message, "expired")
	_, err = guard.SubmitPluginApproval(context.Background(), l.dbs["product_a"].db, guard.PluginApprovalResponse{ApprovalID: a.ID, Assertion: as})
	require.Error(t, err, "the signature comes too late")
	l.record(t, f, f.plugins(nil))
	require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING"}, kindsOf(l.events(t, "product_a")))
}

// A signed approval that differs from what the engine derives in any
// matched field is withheld with PLUGIN_APPROVAL_MISMATCH naming that field
// and never its value. One case per field the guard lets a detail lie in.
func TestChangedEntryIsWithheld(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		field string
		hooks string
		lie   func(*guard.PluginApprovalDetail, *guard.PluginSettings)
		value string
	}{
		{"version", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) { d.Version = "1.4.1" }, "1.4.1"},
		{"manifestSha256", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) {
			d.ManifestSHA256 = strings.Repeat("cd", 32)
		}, "cdcd"},
		{"settingsSha256", feedHooks, func(_ *guard.PluginApprovalDetail, s *guard.PluginSettings) { v := 400; s.TimeoutMs = &v }, "400"},
		{"hooks", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) { d.Hooks = []string{"approval.deliver"} }, "approval.deliver"},
		{"roles", detectHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) { d.Roles = []string{"NAME_CUE", "VALUE"} }, "NAME_CUE"},
		{"endpoint", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) {
			d.Endpoint, d.Isolation = guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "ner.acme.example:443"}, nil
		}, "ner.acme.example"},
		{"egress", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) {
			d.Egress = []string{"ner.acme.example:443"}
		}, "ner.acme.example"},
		{"isolation", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) {
			d.Isolation = &guard.PluginIsolation{Files: guard.PluginFilesOSUser, Network: guard.PluginNetworkEnforced}
		}, "OS_USER"},
		{"signer", feedHooks, func(d *guard.PluginApprovalDetail, _ *guard.PluginSettings) {
			d.Signer, d.SignerKeyID = guard.PluginSignerKnown, "jNZPxNG5htlwfhg4ZgknAA"
		}, "jNZPx"},
	} {
		t.Run(c.field, func(t *testing.T) {
			t.Parallel()
			f := newPluginFixture(t)
			p := f.installApproval(c.hooks, "product_a")
			l := newPluginLedgers(t, f)
			d, s := honestDetail(p, l.roles["product_a"]), p.ApprovalSettings()
			if c.hooks == detectHooks {
				d.Hooks, d.Roles = []string{"wire.detect"}, []string{"VALUE"}
			}
			c.lie(&d, &s)
			l.sign(t, l.person(t), "product_a", l.open(t, "product_a", d, s))

			ep := f.plugins(nil)
			l.record(t, f, ep)
			require.Empty(t, servedTo(ep, p.Key()))
			prob := problemFor(t, ep, "product_a")
			require.Equal(t, agent.ProblemPluginApprovalMismatch, prob.Code)
			require.Contains(t, prob.Message, c.field)
			require.NotContains(t, prob.Message, c.value, "the mismatch names fields, never a value")
			require.NotContains(t, kindsOf(l.events(t, "product_a")), "PLUGIN_ENABLED")
		})
	}

	// Settings changed in engine.json after the entry was approved and
	// served: withheld, PLUGIN_DISABLED written, and that ends the approval,
	// so changing the settings back needs a new one.
	t.Run("settings changed after serving", func(t *testing.T) {
		t.Parallel()
		f := newPluginFixture(t)
		p := f.installApproval(feedHooks, "product_a")
		l := newPluginLedgers(t, f)
		pk := l.person(t)
		l.approve(t, pk, p, "product_a")
		l.record(t, f, f.plugins(nil))
		require.Equal(t, "PLUGIN_ENABLED", kindsOf(l.events(t, "product_a"))[2])

		f.cfg.Plugins[0].TimeoutMs = 400
		ep := f.plugins(nil)
		l.record(t, f, ep)
		require.Empty(t, servedTo(ep, p.Key()))
		prob := problemFor(t, ep, "product_a")
		require.Equal(t, agent.ProblemPluginApprovalMismatch, prob.Code)
		require.Contains(t, prob.Message, "settingsSha256")
		// The next start finds that approval ended by the PLUGIN_DISABLED, and
		// writes nothing more.
		ep = f.plugins(nil)
		l.record(t, f, ep)
		require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "product_a").Code)
		rows := l.events(t, "product_a")
		require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING", "PLUGIN_APPROVED", "PLUGIN_ENABLED", "PLUGIN_DISABLED"}, kindsOf(rows))
		require.JSONEq(t, rows[2].Detail, rows[3].Detail, "PLUGIN_DISABLED carries what was last recorded")

		f.cfg.Plugins[0].TimeoutMs = p.TimeoutMs
		ep = f.plugins(nil)
		l.record(t, f, ep)
		require.Empty(t, servedTo(ep, p.Key()), "the disable ended the approval")
		require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "product_a").Code)
	})
}

// approvalMismatch names each matched field that differs, the ones the
// guard would not let a detail lie in included.
func TestApprovalMismatchNamesEveryField(t *testing.T) {
	t.Parallel()
	base := guard.PluginApprovalBound{
		Name: "acme-ner", Instance: "default", Version: "1.4.0", ManifestSHA256: strings.Repeat("ab", 32),
		SettingsSHA256: strings.Repeat("01", 32), Hooks: []string{"wire.detect"}, Roles: []string{"VALUE"},
		Egress: []string{}, Endpoint: guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
		Signer:    guard.PluginSignerKnown, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA",
	}
	require.Empty(t, approvalMismatch(base, base))
	nilEgress := base
	nilEgress.Egress = nil
	require.Empty(t, approvalMismatch(base, nilEgress), "no egress and an empty egress are the same")
	for field, change := range map[string]func(*guard.PluginApprovalBound){
		"name":           func(b *guard.PluginApprovalBound) { b.Name = "other" },
		"instance":       func(b *guard.PluginApprovalBound) { b.Instance = "client_x" },
		"version":        func(b *guard.PluginApprovalBound) { b.Version = "1.4.1" },
		"manifestSha256": func(b *guard.PluginApprovalBound) { b.ManifestSHA256 = strings.Repeat("cd", 32) },
		"settingsSha256": func(b *guard.PluginApprovalBound) { b.SettingsSHA256 = strings.Repeat("02", 32) },
		"hooks":          func(b *guard.PluginApprovalBound) { b.Hooks = []string{"feed.observe"} },
		"roles":          func(b *guard.PluginApprovalBound) { b.Roles = []string{"NAME_CUE", "VALUE"} },
		"endpoint":       func(b *guard.PluginApprovalBound) { b.Endpoint.Kind = guard.PluginEndpointRemote },
		"egress":         func(b *guard.PluginApprovalBound) { b.Egress = []string{"x.example:443"} },
		"isolation":      func(b *guard.PluginApprovalBound) { b.Isolation = &guard.PluginIsolation{Files: guard.PluginFilesNone} },
		"signer":         func(b *guard.PluginApprovalBound) { b.Signer = guard.PluginSignerUnknown },
		"signerKeyId":    func(b *guard.PluginApprovalBound) { b.SignerKeyID = "other" },
	} {
		got := base
		got.Hooks, got.Roles, got.Egress = slices.Clone(base.Hooks), slices.Clone(base.Roles), slices.Clone(base.Egress)
		change(&got)
		require.Equal(t, []string{field}, approvalMismatch(base, got), field)
		require.Equal(t, []string{field}, approvalMismatch(got, base), field)
	}
	noIsolation := base
	noIsolation.Isolation = nil
	require.Equal(t, []string{"isolation"}, approvalMismatch(base, noIsolation))
	host := base
	host.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "a.example:443"}
	other := host
	other.Endpoint.Host = "b.example:443"
	require.Equal(t, []string{"endpoint"}, approvalMismatch(host, other))
}

// An agent removed from an approved entry is no longer served (and gets
// PLUGIN_DISABLED); the agent that stays is still served with no new
// approval and nothing new in its ledger.
func TestRemovedAgentKeepsOthers(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), p, "product_a", "client_x")
	l.record(t, f, f.plugins(nil))
	before := kindsOf(l.events(t, "product_a"))

	f.cfg.Plugins[0].Agents = []string{"product_a"}
	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
	requireNotWithheld(t, ep, p.Key(), "product_a")
	require.Empty(t, ep.PluginProblems("client_x"), "no longer listed, so nothing to report")
	require.Equal(t, before, kindsOf(l.events(t, "product_a")))
	cx := kindsOf(l.events(t, "client_x"))
	require.Equal(t, "PLUGIN_DISABLED", cx[len(cx)-1])
}

// Turning an approved entry off and on again, the same copy, agents and
// settings, is withheld until a new approval is signed: the
// PLUGIN_DISABLED of the off ended the old one.
func TestReenableNeedsNewApproval(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a")
	l.record(t, f, f.plugins(nil))

	f.cfg.Plugins[0].Enabled = false
	l.record(t, f, f.plugins(nil))
	f.cfg.Plugins[0].Enabled = true
	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	prob := problemFor(t, ep, "product_a")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, prob.Code)
	require.Contains(t, prob.Message, "turned off")
	require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING", "PLUGIN_APPROVED", "PLUGIN_ENABLED", "PLUGIN_DISABLED"}, kindsOf(l.events(t, "product_a")))

	l.approve(t, pk, p, "product_a")
	ep = f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
}

// On an agent-operated engine every entry requires approval, also one
// without the key and one signed by a key in the trust store: that key
// makes no publisher known there, and removing it from the store withholds
// nothing once the entry is approved.
func TestAgentOperatedRequiresApprovalAlways(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.cfg.OperatedBy = mcpcontract.OperatedByAgent
	p := f.installCopy("default", feedHooks, true)
	p.Agents = []string{"product_a"}
	f.cfg.Plugins = append(f.cfg.Plugins, p)
	require.Empty(t, p.Approval)
	l := newPluginLedgers(t, f)

	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Empty(t, servedTo(ep, p.Key()))
	require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "product_a").Code)
	require.NotContains(t, kindsOf(l.events(t, "product_a")), "PLUGIN_ENABLED")

	l.approve(t, l.person(t), p, "product_a") // signer UNKNOWN: the trust store does not count
	ep = f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))

	keys, err := f.trust.AddedKeys()
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(f.trust.Dir(), keys[0]+".pem")))
	ep = f.plugins(nil)
	for range 2 {
		l.record(t, f, ep)
	}
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()), "the approval takes the place of the trust record")
	require.NotContains(t, kindsOf(l.events(t, "product_a")), "PLUGIN_DISABLED")
}

// An entry whose agents are on two databases is served to the agent whose
// database holds its approval, and withheld from the other.
func TestServedPerDatabase(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := pluginLedgers{roles: map[string]string{}, dbs: map[string]pluginLedger{}}
	dbs := map[string]*guardtest.DB{}
	for _, a := range f.cfg.Agents {
		d := guardtest.New(t).WithDemo(t)
		ag := d.NewAgent(t, a.Name, demoTables, nil)
		dbs[a.Name], l.roles[a.Name], l.dbs[a.Name] = d, ag.Role, pluginLedger{db: ag.Conn}
	}
	l.approve(t, registerPerson(t, dbs["product_a"]), p, "product_a")

	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
	requireNotWithheld(t, ep, p.Key(), "product_a")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "client_x").Code)
}

// An agent's approval of an entry never takes it from, or changes what is
// served to, an agent it does not name: client_x opens one naming only
// itself, pending (so the engine writes client_x's PLUGIN_DISABLED, which
// ends the shared approval for client_x only) and then signed with another
// version. product_a stays served on its own approval with nothing new in
// its ledger.
func TestApprovalOfAnotherAgentLeavesThisOne(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a", "client_x")
	l.record(t, f, f.plugins(nil))
	before := l.events(t, "product_a")

	l.open(t, "client_x", honestDetail(p, l.roles["client_x"]), p.ApprovalSettings())
	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
	requireNotWithheld(t, ep, p.Key(), "product_a")
	require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "client_x").Code)
	cx := kindsOf(l.events(t, "client_x"))
	require.Equal(t, "PLUGIN_DISABLED", cx[len(cx)-1], "client_x stopped being served")

	d := honestDetail(p, l.roles["client_x"])
	d.Version = "1.4.1"
	l.sign(t, pk, "client_x", l.open(t, "client_x", d, p.ApprovalSettings()))
	ep = f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
	requireNotWithheld(t, ep, p.Key(), "product_a")
	require.Equal(t, agent.ProblemPluginApprovalMismatch, problemFor(t, ep, "client_x").Code)
	require.Equal(t, before, l.events(t, "product_a"), "nothing new in product_a's ledger")
}

// An entry that does not require approval is served as before: an unsigned
// copy is refused, a signed one needs its key on record, its record has no
// signer, and an approval in the database changes nothing.
func TestEntryWithoutApprovalUnchanged(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	signed := f.install("default", dial.TransportStdio, "product_a")
	unsigned := f.installCopy("client_x", feedHooks, false)
	unsigned.Agents = []string{"product_a"}
	f.cfg.Plugins = append(f.cfg.Plugins, unsigned)
	l := newPluginLedgers(t, f)
	ro := l.roles["product_a"]
	l.sign(t, l.person(t), "product_a", l.open(t, "product_a", honestDetail(unsigned, ro), unsigned.ApprovalSettings()))

	ep := f.plugins(nil)
	l.record(t, f, ep)
	require.Equal(t, []string{"product_a"}, servedTo(ep, signed.Key()))
	require.Empty(t, servedTo(ep, unsigned.Key()))
	var unsignedCode string
	for _, pr := range ep.PluginProblems("product_a") {
		if pr.Instance == "client_x" {
			unsignedCode = pr.Code
		}
	}
	require.Equal(t, agent.ProblemPluginNotTrusted, unsignedCode, "unsigned and not required: refused as before")
	rows := l.events(t, "product_a")
	require.Equal(t, []string{"PLUGIN_APPROVAL_PENDING", "PLUGIN_APPROVED", "PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(rows))
	require.NotContains(t, rows[3].Detail, "signer\"", "no signer for an entry that does not require approval")
	require.Contains(t, rows[3].Detail, "signerKeyId")
}

// A guard older than schema version 5, or approvals that cannot be read,
// withhold the entry with PLUGIN_UNAVAILABLE and write nothing, so an
// approved entry's approval does not end; the next start serves it again.
func TestApprovalsUnreadableWriteNothing(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		breaks, mends string
		want          string
	}{
		"guard older than 5": {
			`DELETE FROM basalt_meta.schema_version WHERE version >= 5`,
			`INSERT INTO basalt_meta.schema_version (version) VALUES (5)`,
			"schema version 5",
		},
		"view not readable": {
			`REVOKE SELECT ON basalt_meta.agent_plugin_approvals FROM ` + "%s",
			`GRANT SELECT ON basalt_meta.agent_plugin_approvals TO ` + "%s",
			"could not be read",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPluginFixture(t)
			p := f.installApproval(feedHooks, "product_a")
			l := newPluginLedgers(t, f)
			l.approve(t, l.person(t), p, "product_a")
			l.record(t, f, f.plugins(nil))
			before := kindsOf(l.events(t, "product_a"))
			require.Equal(t, "PLUGIN_ENABLED", before[len(before)-1])

			group := l.d.Names.Agents()
			l.d.Exec(t, strings.ReplaceAll(c.breaks, "%s", group))
			ep := f.plugins(nil)
			l.record(t, f, ep)
			require.Empty(t, servedTo(ep, p.Key()))
			prob := problemFor(t, ep, "product_a")
			require.Equal(t, agent.ProblemPluginUnavailable, prob.Code)
			require.Contains(t, prob.Message, c.want)
			if name == "guard older than 5" {
				require.Contains(t, prob.Message, "basalt upgrade")
			}
			require.Equal(t, before, kindsOf(l.events(t, "product_a")), "nothing written: the approval does not end")

			l.d.Exec(t, strings.ReplaceAll(c.mends, "%s", group))
			ep = f.plugins(nil)
			l.record(t, f, ep)
			require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
		})
	}
}

// An entry an agent's basalt plugin add wrote with the approval key, whose
// copy a key in the person's trust store signed, is withheld until a
// person signs an approval: the trust store vouches for nothing here, and
// no trust record is written for it.
func TestTrustedSignerWithoutApprovalIsWithheld(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installCopy("default", feedHooks, true)
	p.Agents, p.Approval = []string{"product_a"}, config.PluginApprovalRequired
	f.cfg.Plugins = append(f.cfg.Plugins, p)
	l := newPluginLedgers(t, f)

	ep := f.plugins(nil)
	for range 2 {
		l.record(t, f, ep)
	}
	require.Empty(t, servedTo(ep, p.Key()))
	require.Empty(t, ep.entries)
	require.Equal(t, agent.ProblemPluginAwaitingApproval, problemFor(t, ep, "product_a").Code)
	require.NotContains(t, kindsOf(l.events(t, "product_a")), "PLUGIN_ENABLED")
}

// basalt plugin and the engine derive the detail and the settings with the
// same functions (PluginApprovalDetail, config.Plugin.ApprovalSettings): an
// approval opened from them and signed is served, for a local and a remote
// plugin, with numbers the guard rewrites (0.60, 1e3).
func TestCommandsApprovalIsServed(t *testing.T) {
	t.Parallel()
	for name, remote := range map[string]bool{"local": false, "remote": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPluginFixture(t)
			var p config.Plugin
			if remote {
				p = f.installRemote()
			} else {
				p = f.installCopy("default", detectHooks, false)
			}
			mc := 0.60
			p.Agents, p.Approval, p.MinConfidence, p.TimeoutMs = []string{"product_a"}, config.PluginApprovalRequired, &mc, 1500
			p.Config = json.RawMessage(`{"threshold": 0.60, "max": 1e3}`)
			if remote {
				p.Auth = &config.PluginAuth{CredentialFile: "/etc/basalt/acme.token"}
			}
			f.cfg.Plugins = append(f.cfg.Plugins, p)
			l := newPluginLedgers(t, f)

			v, err := plugin.Verify(f.root, p.Key(), p.ManifestSHA256, f.trust, plugin.ModeSameUser, plugin.RequireApproval(true))
			require.NoError(t, err)
			d := PluginApprovalDetail(p.Key(), v, []string{l.roles["product_a"]})
			l.sign(t, l.person(t), "product_a", l.open(t, "product_a", d, p.ApprovalSettings()))

			ep := f.plugins(nil)
			l.record(t, f, ep)
			require.Equal(t, []string{"product_a"}, servedTo(ep, p.Key()))
			require.Empty(t, ep.unrecordedFor(p.Key(), "product_a"))
		})
	}
}

// installRemote installs a copy of a remote plugin manifest with no .sig
// and returns its entry with no agents.
func (f *pluginFixture) installRemote() config.Plugin {
	f.t.Helper()
	t := f.t
	src := t.TempDir()
	manifest := `{
  "manifestVersion": 1, "name": "acme-ner", "version": "2.0.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "feed.observe": { "contract": "feed/1" } },
  "endpoint": { "remote": { "transport": "connectrpc", "url": "https://ner.acme.example/v1" } },
  "network": { "egress": ["ner.acme.example:443"] }
}
`
	require.NoError(t, os.WriteFile(filepath.Join(src, plugin.ManifestFile), []byte(manifest), 0o644))
	v, err := plugin.Install(src, f.root, "default", f.trust, plugin.ModeSameUser, plugin.RequireApproval(true))
	require.NoError(t, err)
	return config.Plugin{Name: "acme-ner", Instance: "default", ManifestSHA256: v.ManifestSHA256, Enabled: true, Agents: []string{}}
}

// Default deny: an entry that requires approval is served to no agent whose
// approvals were never read, an agent with no ledger or one not admitted,
// even though a matching approval exists.
func TestRequiredEntryDeniedWithoutALedger(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	l.approve(t, l.person(t), p, "product_a", "client_x")

	ep := f.plugins(nil)
	require.Empty(t, servedTo(ep, p.Key()), "no agent before the check")
	ledgers := map[string]pluginLedger{
		"product_a": {db: l.dbs["product_a"].db, admit: func(context.Context) error { return errNotAdmitted }},
	}
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, ledgers, slog.New(slog.DiscardHandler))
	require.Empty(t, servedTo(ep, p.Key()))
	require.Empty(t, ep.entries)
	for _, a := range []string{"product_a", "client_x"} {
		require.Equal(t, agent.ProblemPluginUnavailable, problemFor(t, ep, a).Code, a)
	}
}

// A withheld entry blocks none of the agent's calls: the agent is admitted,
// starts a run and reads its status, which names the entry with the
// catalog's steps.
func TestWithheldEntryBlocksNoAgentCall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, nil)
	r := newRemoteAgent(t, a.URL, guard.SetupAgent)
	cfg, err := config.Load(r.cfgPath)
	require.NoError(t, err)

	f := newPluginFixture(t)
	f.cfg = cfg
	f.cfg.Plugins = nil
	p := f.installApproval(feedHooks, "bot")
	ep := f.plugins(nil)
	env := agentEnv{cfg: f.cfg, configPath: r.cfgPath, pagesBase: links.DefaultLocal, stateDir: r.dir, pins: &chainpin.Memory{}, plugins: ep}
	srv, err := startAgents(ctx, f.cfg, env, map[string]uint32{"bot": 5001}, newAgentRuntime, slog.New(slog.DiscardHandler))
	t.Cleanup(func() {
		for _, c := range srv.closers {
			c()
		}
	})
	require.NoError(t, err)
	recordPluginEvents(ctx, f.cfg, f.configPath, ep, srv.pluginLedgers, slog.New(slog.DiscardHandler))
	require.Empty(t, servedTo(ep, p.Key()))

	svc := srv.services[0]
	require.NoError(t, svc.Admit(ctx))
	_, err = svc.StartRun(ctx, "check the leads", uuid.Nil)
	require.NoError(t, err)
	st, err := svc.Status(ctx)
	require.NoError(t, err)
	require.Contains(t, problemCodes(st), agent.ProblemPluginAwaitingApproval)
}
