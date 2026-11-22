//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// pluginLedgers is a guard with the fixture's two agents, each with its own
// connection, as the engine holds them.
type pluginLedgers struct {
	d     *guardtest.DB
	roles map[string]string
	dbs   map[string]pluginLedger
	urls  map[string]string
}

func newPluginLedgers(t *testing.T, f *pluginFixture) pluginLedgers {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	l := pluginLedgers{d: d, roles: map[string]string{}, dbs: map[string]pluginLedger{}, urls: map[string]string{}}
	for _, a := range f.cfg.Agents {
		ag := d.NewAgent(t, a.Name, demoTables, nil)
		l.roles[a.Name], l.dbs[a.Name], l.urls[a.Name] = ag.Role, pluginLedger{db: ag.Conn}, ag.URL
	}
	return l
}

// events are an agent's plugin ledger rows, oldest first, as kind and raw
// detail, read as the admin.
type pluginRow struct {
	Kind   string
	Detail string
}

func (l pluginLedgers) events(t *testing.T, agentName string) []pluginRow {
	t.Helper()
	// Plain SQL: a fixture read of the guard's own table.
	rows, err := l.d.Admin.Query(context.Background(), `SELECT kind, detail::text FROM basalt_meta.ledger
		WHERE agent = $1 AND kind LIKE 'PLUGIN\_%' ORDER BY seq`, l.roles[agentName])
	require.NoError(t, err)
	defer rows.Close()
	var out []pluginRow
	for rows.Next() {
		var r pluginRow
		require.NoError(t, rows.Scan(&r.Kind, &r.Detail))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func kindsOf(rows []pluginRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Kind)
	}
	return out
}

// withheldBy is writePluginEvents's withheld entries per agent.
func withheldBy(ctx context.Context, want pluginWant, ledgers map[string]pluginLedger, log *slog.Logger) map[string][]unrecordedEntry {
	withheld := map[string][]unrecordedEntry{}
	for name, p := range writePluginEvents(ctx, want, ledgers, log) {
		if len(p.withheld) > 0 {
			withheld[name] = p.withheld
		}
	}
	return withheld
}

func (l pluginLedgers) record(t *testing.T, f *pluginFixture, ep *enginePlugins) {
	t.Helper()
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, l.dbs, slog.New(slog.DiscardHandler))
}

// A served entry is recorded PLUGIN_ENABLED once in each listed agent's
// ledger; a restart with no change writes nothing new.
func TestEnabledWrittenOnce(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	for range 3 {
		l.record(t, f, f.plugins(nil))
	}
	for _, a := range []string{"product_a", "client_x"} {
		rows := l.events(t, a)
		require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(rows), a)
		var d guard.PluginDetail
		require.NoError(t, json.Unmarshal([]byte(rows[1].Detail), &d))
		require.Equal(t, p.ManifestSHA256, d.ManifestSHA256)
		require.Equal(t, "default", d.Instance)
		require.Equal(t, []string{"feed.observe"}, d.Hooks)
		require.Equal(t, guard.PluginEndpoint{Kind: guard.PluginEndpointLocal}, d.Endpoint)
		require.Equal(t, &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced}, d.Isolation,
			"same-user mode: no file or network isolation")
	}
}

// An agent removed from an entry's agents gets PLUGIN_DISABLED in its own
// ledger, once; the agent still listed gets nothing new. Disabling the
// entry then disables it for the other agent too.
func TestRemovedAgentGetsDisabled(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))

	f.cfg.Plugins[0].Agents = []string{"product_a"}
	for range 2 {
		l.record(t, f, f.plugins(nil))
	}
	cx := l.events(t, "client_x")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_DISABLED"}, kindsOf(cx))
	require.JSONEq(t, cx[1].Detail, cx[2].Detail, "PLUGIN_DISABLED carries what was last recorded")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))

	f.cfg.Plugins[0].Enabled = false
	require.Nil(t, f.plugins(nil), "no entry is enabled")
	for range 2 {
		l.record(t, f, nil)
	}
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_DISABLED"}, kindsOf(l.events(t, "product_a")))
	require.Len(t, l.events(t, "client_x"), 3)

	// Enabled again: PLUGIN_ENABLED again, for the agent listed.
	f.cfg.Plugins[0].Enabled = true
	l.record(t, f, f.plugins(nil))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_DISABLED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))
	require.Len(t, l.events(t, "client_x"), 3)
}

// No agent's ledger names another agent, and no detail holds the entry's
// config, its credential file or any path.
func TestDetailNeverNamesOtherAgents(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a", "client_x")
	f.install("eu", dial.TransportUnix, "client_x")
	f.cfg.Plugins[0].Config = json.RawMessage(`{"languages": ["tagalog-secret-value"]}`)
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	f.cfg.Plugins[0].Agents = []string{"client_x"}
	l.record(t, f, f.plugins(nil))

	for _, a := range []string{"product_a", "client_x"} {
		rows := l.events(t, a)
		require.NotEmpty(t, rows)
		for _, r := range rows {
			for _, other := range []string{"product_a", "client_x"} {
				require.NotContains(t, r.Detail, other, "%s's ledger", a)
			}
			require.NotContains(t, r.Detail, "tagalog-secret-value")
			require.NotContains(t, r.Detail, f.root)
			require.NotContains(t, r.Detail, "bin/p")
		}
	}
}

// PLUGIN_TRUST_ADDED goes to every agent, listed by an entry or not, once
// per key; a key added later is recorded at the next start.
func TestTrustAddedToEveryAgent(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	f.install("eu", dial.TransportStdio, "product_a")
	l.record(t, f, f.plugins(nil))
	l.record(t, f, f.plugins(nil))

	keys, err := f.trust.AddedKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	for _, a := range []string{"product_a", "client_x"} {
		var got []string
		for _, r := range l.events(t, a) {
			if r.Kind != string(guard.PluginTrustAdded) {
				continue
			}
			var d struct {
				SignerKeyID string `json:"signerKeyId"`
			}
			require.NoError(t, json.Unmarshal([]byte(r.Detail), &d))
			got = append(got, d.SignerKeyID)
		}
		require.ElementsMatch(t, keys, got, a)
	}
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_TRUST_ADDED"}, kindsOf(l.events(t, "client_x")), "listed by no entry")
}

// A change to a served entry's record is PLUGIN_CHANGED, once.
func TestChangedEntryWritesChanged(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	ep := f.plugins(nil)
	discard := slog.New(slog.DiscardHandler)
	want := wantedPlugins(f.cfg, ep, trustedKeys(f.cfg, f.configPath, discard))
	require.Empty(t, withheldBy(context.Background(), want, l.dbs, discard))
	d := want.served["product_a"][p.Key()]
	d.Egress = []string{"ner.acme.example:443"}
	want.served["product_a"][p.Key()] = d
	for range 2 {
		require.Empty(t, withheldBy(context.Background(), want, l.dbs, discard))
	}
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_CHANGED"}, kindsOf(l.events(t, "product_a")))
}

// An entry enabled and listed that the engine does not start (it fails
// verification) while the key that signed it is still trusted keeps its
// record: no PLUGIN_DISABLED for a passing failure.
func TestHeldEntryKeepsItsRecord(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	require.NoError(t, os.WriteFile(f.installedFile(p), []byte("changed"), 0o755))
	ep := f.plugins(nil)
	require.Equal(t, []string{agent.ProblemPluginNotTrusted}, codes(ep.PluginProblems("product_a")))
	for range 2 {
		l.record(t, f, ep)
	}
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))
}

// An entry held because the key that signed it was removed from the trust
// store gets PLUGIN_TRUST_REMOVED for the key and PLUGIN_DISABLED for the
// entry, once: the ledger never shows it served without its key.
func TestHeldEntryOfRemovedKeyGetsDisabled(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	keys, err := f.trust.AddedKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.NoError(t, os.Remove(filepath.Join(f.trust.Dir(), keys[0]+".pem")))

	ep := f.plugins(nil)
	require.Equal(t, []string{agent.ProblemPluginNotTrusted}, codes(ep.PluginProblems("product_a")), "held: its key is gone")
	for range 2 {
		l.record(t, f, ep)
	}
	rows := l.events(t, "product_a")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_TRUST_REMOVED", "PLUGIN_DISABLED"}, kindsOf(rows))
	require.JSONEq(t, rows[1].Detail, rows[3].Detail, "PLUGIN_DISABLED carries what was last recorded")
	recs, err := guard.ReadPluginRecords(context.Background(), l.dbs["product_a"].db)
	require.NoError(t, err)
	require.Empty(t, recs.TrustKeys)
	for _, r := range recs.Entries {
		require.False(t, r.Enabled(), "no entry is on record as served")
	}
}

// When an agent's record cannot be written, the entry is not served to
// that agent (the host refuses a call naming it, and status shows
// PLUGIN_UNAVAILABLE) and still serves the agent whose record was written.
// The next start writes it.
func TestUnrecordedEntryIsNotServed(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a", "client_x")
	l := newPluginLedgers(t, f)
	broken := map[string]pluginLedger{"product_a": l.dbs["product_a"], "client_x": {db: l.d.Admin}} // not an agent role: refused
	ep := f.plugins(nil)
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, broken, slog.New(slog.DiscardHandler))
	require.Empty(t, l.events(t, "client_x"))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))

	runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	require.Empty(t, ep.PluginProblems("product_a"))
	probs := ep.PluginProblems("client_x")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(probs))
	require.Contains(t, probs[0].Message, "the guard refused its plugin record")
	require.NotContains(t, probs[0].Message, "product_a")
	err := ep.host.Call(context.Background(), p.Key(), []string{"client_x"}, "detect", nil, nil)
	require.ErrorIs(t, err, plugin.ErrAgentNotListed, "the host refuses a call naming the withheld agent")

	// The only listed agent unrecorded: the entry does not start at all.
	solo := newPluginFixture(t)
	q := solo.install("default", dial.TransportStdio, "client_x")
	ep = solo.plugins(nil)
	recordPluginEvents(context.Background(), solo.cfg, solo.configPath, ep, map[string]pluginLedger{}, slog.New(slog.DiscardHandler))
	require.Empty(t, ep.entries)
	probs = ep.PluginProblems("client_x")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(probs))
	require.Contains(t, probs[0].Message, "database is reachable")
	require.NotEqual(t, plugin.StateReady, ep.host.State(q.Key()))

	// Next start, database reachable: recorded and served.
	l.record(t, f, f.plugins(nil))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "client_x")))
}

// What the engine records validates against the contract's events schema,
// for a local and a remote entry.
func TestPluginDetailMatchesTheSchema(t *testing.T) {
	t.Parallel()
	const base = "https://basaltvault.app/schemas/plugin/"
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for _, name := range []string{"manifest.schema.json", "events.schema.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "api", "plugin", name))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(base+name, doc))
	}
	sch, err := c.Compile(base + "events.schema.json")
	require.NoError(t, err)

	k := plugin.EntryKey{Name: "acme-ner", Instance: "client_x"}
	sha := strings.Repeat("ab", 32)
	local := plugin.Manifest{
		Name: "acme-ner", Version: "1.4.0", Hooks: map[string]protocol.HookDecl{"wire.detect": {Roles: []string{"NAME_CUE", "VALUE"}}},
		Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: dial.TransportStdio, Command: "bin/p"}},
	}
	remote := plugin.Manifest{
		Name: "acme-ner", Version: "2.0.0-rc.1", Hooks: map[string]protocol.HookDecl{"feed.observe": {}, "approval.deliver": {}},
		Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: dial.TransportConnect, URL: "https://ner.acme.example/v1"}},
		Network:  plugin.Network{Egress: []string{"ner.acme.example:443"}},
	}
	for _, m := range []plugin.Manifest{local, remote} {
		d := pluginDetail(k, plugin.Verified{Manifest: m, ManifestSHA256: sha, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA"}, plugin.ModeSameUser, "linux")
		for _, kind := range []guard.PluginEventKind{guard.PluginEnabled, guard.PluginDisabled, guard.PluginChanged} {
			b, err := json.Marshal(map[string]any{"kind": kind, "detail": d})
			require.NoError(t, err)
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			require.NoError(t, err)
			require.NoError(t, sch.Validate(inst), string(b))
		}
	}
	d := pluginDetail(k, plugin.Verified{Manifest: remote, ManifestSHA256: sha, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA"}, plugin.ModeSameUser, "linux")
	require.Equal(t, guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "ner.acme.example:443"}, d.Endpoint)
	require.Nil(t, d.Isolation, "a remote entry records no local isolation")
	require.Equal(t, []string{"approval.deliver", "feed.observe"}, d.Hooks)
}

// The engine's own runtime gives the plugin writer the agent's ledger:
// startAgents maps each agent to its pool and its admission, and an
// admitted agent's record is written through them.
func TestRuntimeLedgerRecordsPluginEvents(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, nil)
	r := newRemoteAgent(t, a.URL, guard.SetupAgent)
	cfg, err := config.Load(r.cfgPath)
	require.NoError(t, err)
	env := agentEnv{cfg: cfg, configPath: r.cfgPath, pagesBase: links.DefaultLocal, stateDir: r.dir, pins: &chainpin.Memory{}}
	srv, err := startAgents(context.Background(), cfg, env, map[string]uint32{"bot": 5001}, newAgentRuntime, slog.New(slog.DiscardHandler))
	t.Cleanup(func() {
		for _, c := range srv.closers {
			c()
		}
	})
	require.NoError(t, err)
	l, ok := srv.pluginLedgers["bot"]
	require.True(t, ok, "the runtime's ledger reaches the plugin writer")
	require.NotNil(t, l.db)
	require.NotNil(t, l.admit)

	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	want := pluginWant{
		served: map[string]map[plugin.EntryKey]guard.PluginDetail{"bot": {k: testDetail(k)}},
		held:   map[string]map[plugin.EntryKey]bool{"bot": {}},
		trust:  trustWant{read: true, added: []string{testDetail(k).SignerKeyID}},
	}
	require.Empty(t, withheldBy(context.Background(), want, srv.pluginLedgers, slog.New(slog.DiscardHandler)))
	recs, err := guard.ReadPluginRecords(context.Background(), a.Conn)
	require.NoError(t, err)
	require.Equal(t, []guard.PluginDetail{testDetail(k)}, recs.EnabledPlugins())

	// An agent served status only (a pending install setup) gets no record
	// and no plugin, with the reason.
	pending := newRemoteAgent(t, d.NewAgent(t, "other", demoTables, nil).URL, guard.SetupInstall)
	rt := pending.start(t)
	got := withheldBy(context.Background(), pluginWant{
		served: map[string]map[plugin.EntryKey]guard.PluginDetail{"bot": {k: testDetail(k)}},
		held:   map[string]map[plugin.EntryKey]bool{"bot": {}},
	}, map[string]pluginLedger{"bot": {db: rt.db, admit: pluginAdmit(rt.svc)}}, slog.New(slog.DiscardHandler))
	require.Equal(t, map[string][]unrecordedEntry{"bot": {{key: k, why: whyNotAdmitted}}}, got)
}

func testDetail(k plugin.EntryKey) guard.PluginDetail {
	return guard.PluginDetail{
		Name: k.Name, Instance: k.Instance, Version: "1.4.0", ManifestSHA256: strings.Repeat("ab", 32),
		SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA", Hooks: []string{"feed.observe"}, Egress: []string{},
		Endpoint:  guard.PluginEndpoint{Kind: guard.PluginEndpointLocal},
		Isolation: &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced},
	}
}

// On a guard older than schema version 3 the record cannot be written:
// the entry is withheld from that agent and its status names the upgrade.
func TestOldGuardWithholdsWithTheUpgradeStep(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.d.Exec(t, `DROP FUNCTION basalt_meta.record_plugin_event(text, jsonb)`)
	ep := f.plugins(nil)
	l.record(t, f, ep)
	probs := ep.PluginProblems("product_a")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(probs))
	require.Contains(t, probs[0].Message, "basalt init")
	require.Empty(t, ep.entries)
}

// The largest manifests ParseManifest accepts, local and remote, record on
// the real guard with the longest instance and isolation: no plugin the
// person consents to is refused by the guard.
func TestLargestAcceptedManifestRecords(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, nil)
	version := "1.0.0-" + strings.Repeat("a", 58)
	for _, remote := range []bool{false, true} {
		var m plugin.Manifest
		for n := 1; ; n++ {
			egress := make([]string, 0, n)
			for i := range n {
				egress = append(egress, fmt.Sprintf("%s%02d.example:443", strings.Repeat("h", 60), i))
			}
			endpoint := `{"local": {"transport": "jsonrpc-stdio", "command": "bin/p"}}`
			if remote {
				endpoint = `{"remote": {"transport": "connectrpc", "url": "https://` + strings.TrimSuffix(egress[0], ":443") + `"}}`
			}
			eg, err := json.Marshal(egress)
			require.NoError(t, err)
			raw := `{"manifestVersion": 1, "name": "` + strings.Repeat("n", 40) + `", "version": "` + version + `", "publisher": "A",
				"protocol": ["basalt-plugin/1"],
				"hooks": {"wire.detect": {"contract": "detector/1", "roles": ["VALUE", "NAME_CUE"], "entityTypes": ["PERSON_NAME"]}},
				"endpoint": ` + endpoint + `, "files": {"bin/p": "sha256:` + strings.Repeat("0", 64) + `"},
				"network": {"egress": ` + string(eg) + `}}`
			if remote {
				raw = strings.Replace(raw, `"files": {"bin/p": "sha256:`+strings.Repeat("0", 64)+`"},`, "", 1)
			}
			next, err := plugin.ParseManifest([]byte(raw))
			if err != nil {
				require.ErrorContains(t, err, "too large to record")
				break
			}
			m = next
		}
		require.NotEmpty(t, m.Network.Egress)
		k := plugin.EntryKey{Name: m.Name, Instance: strings.Repeat("i", 32)}
		det := pluginDetail(k, plugin.Verified{Manifest: m, ManifestSHA256: strings.Repeat("ab", 32), SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA"}, plugin.ModeSameUser, "linux")
		if det.Isolation != nil {
			det.Isolation = &guard.PluginIsolation{Files: guard.PluginFilesOSUser, Network: guard.PluginNetworkNotEnforced}
		}
		require.NoError(t, guard.RecordPluginEntryEvent(context.Background(), a.Conn, guard.PluginEnabled, det), "remote %v", remote)
	}
}

// A local entry records the isolation it runs with: same-user mode none;
// service mode its own OS user, with the network its unit gets (the unit
// rule, service.PluginNetwork). A remote entry records none.
func TestPluginIsolationIsWhatRuns(t *testing.T) {
	t.Parallel()
	local := func(egress ...string) plugin.Manifest {
		return plugin.Manifest{
			Name: "acme-ner", Version: "1.0.0", Hooks: map[string]protocol.HookDecl{"feed.observe": {}},
			Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: dial.TransportStdio, Command: "bin/p"}},
			Network:  plugin.Network{Egress: egress},
		}
	}
	iso := func(files, network string) *guard.PluginIsolation {
		return &guard.PluginIsolation{Files: files, Network: network}
	}
	for _, tc := range []struct {
		name string
		mode plugin.Mode
		goos string
		m    plugin.Manifest
		want *guard.PluginIsolation
	}{
		{"same-user", plugin.ModeSameUser, "linux", local(), iso(guard.PluginFilesNone, guard.PluginNetworkNotEnforced)},
		{"same-user with egress", plugin.ModeSameUser, "darwin", local("x.example:443"), iso(guard.PluginFilesNone, guard.PluginNetworkNotEnforced)},
		{"service linux no egress", plugin.ModeService, "linux", local(), iso(guard.PluginFilesOSUser, guard.PluginNetworkEnforced)},
		{"service linux egress", plugin.ModeService, "linux", local("x.example:443"), iso(guard.PluginFilesOSUser, guard.PluginNetworkDeclared)},
		{"service macos", plugin.ModeService, "darwin", local(), iso(guard.PluginFilesOSUser, guard.PluginNetworkNotEnforced)},
		{"service macos egress", plugin.ModeService, "darwin", local("x.example:443"), iso(guard.PluginFilesOSUser, guard.PluginNetworkNotEnforced)},
	} {
		d := pluginDetail(plugin.EntryKey{Name: "acme-ner", Instance: "default"}, plugin.Verified{Manifest: tc.m}, tc.mode, tc.goos)
		require.Equal(t, tc.want, d.Isolation, tc.name)
	}
	remote := local("ner.acme.example:443")
	remote.Endpoint = plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: dial.TransportConnect, URL: "https://ner.acme.example"}}
	for _, mode := range []plugin.Mode{plugin.ModeSameUser, plugin.ModeService} {
		d := pluginDetail(plugin.EntryKey{Name: "acme-ner", Instance: "default"}, plugin.Verified{Manifest: remote}, mode, "linux")
		require.Nil(t, d.Isolation)
		require.Equal(t, guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "ner.acme.example:443"}, d.Endpoint)
	}
}

// refuseTrustKey is an agent's connection on which the PLUGIN_TRUST_ADDED
// record of one key fails, as a guard that refuses it would; every other
// statement goes through.
type refuseTrustKey struct {
	guard.Querier
	keyID string
}

func (q refuseTrustKey) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(fmt.Sprint(args...), string(guard.PluginTrustAdded)) && strings.Contains(fmt.Sprint(args...), q.keyID) {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "BS008", Message: "refused"}
	}
	return q.Querier.Exec(ctx, sql, args...)
}

// When the PLUGIN_TRUST_ADDED record of a key cannot be written to an
// agent's ledger, the entries signed by that key are withheld from that
// agent, with no PLUGIN_ENABLED for them; an entry signed by another key is
// served. The next start writes the key and serves the entry.
func TestUnrecordedTrustKeyWithholdsItsEntries(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	refused := f.install("default", dial.TransportStdio, "product_a", "client_x")
	other := f.install("eu", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	ep := f.plugins(nil)
	v, ok := ep.startedCopy(refused.Key())
	require.True(t, ok)
	w, ok := ep.startedCopy(other.Key())
	require.True(t, ok)
	require.NotEqual(t, v.SignerKeyID, w.SignerKeyID)

	ledgers := map[string]pluginLedger{
		"product_a": {db: refuseTrustKey{Querier: l.dbs["product_a"].db, keyID: v.SignerKeyID}},
		"client_x":  l.dbs["client_x"],
	}
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, ledgers, slog.New(slog.DiscardHandler))

	rows := l.events(t, "product_a")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(rows), "only the other key and its entry")
	require.Contains(t, rows[0].Detail, w.SignerKeyID)
	require.Contains(t, rows[1].Detail, `"instance": "eu"`)
	require.NotEmpty(t, ep.unrecordedFor(refused.Key(), "product_a"), "withheld from product_a")
	require.Empty(t, ep.unrecordedFor(other.Key(), "product_a"))
	require.Empty(t, ep.unrecordedFor(refused.Key(), "client_x"), "client_x recorded the key: served")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "client_x")))
	var refusedProbs int
	for _, p := range ep.PluginProblems("product_a") {
		require.Equal(t, agent.ProblemPluginUnavailable, p.Code)
		if strings.Contains(p.Message, "the guard refused its plugin record") {
			refusedProbs++
		}
	}
	require.Equal(t, 1, refusedProbs, "status names the withheld entry's reason once")

	// Next start, the guard takes it: the key, then the entry.
	l.record(t, f, f.plugins(nil))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED", "PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))
}

// refuseKind is an agent's connection on which every plugin event of one
// kind is refused with BS008, as a guard without that kind refuses it.
type refuseKind struct {
	guard.Querier
	kind guard.PluginEventKind
}

func (q refuseKind) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(fmt.Sprint(args...), string(q.kind)) {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "BS008", Message: "kind must be one of the older kinds"}
	}
	return q.Querier.Exec(ctx, sql, args...)
}

// forgedKey is a key id no trust store holds.
const forgedKey = "ForgedKeyForgedKey0000"

// trustRows are an agent's trust events, oldest first, as kind and key.
func (l pluginLedgers) trustRows(t *testing.T, agentName string) [][2]string {
	t.Helper()
	var out [][2]string
	for _, r := range l.events(t, agentName) {
		if r.Kind != string(guard.PluginTrustAdded) && r.Kind != string(guard.PluginTrustRemoved) {
			continue
		}
		var d struct {
			SignerKeyID string `json:"signerKeyId"`
		}
		require.NoError(t, json.Unmarshal([]byte(r.Detail), &d))
		out = append(out, [2]string{r.Kind, d.SignerKeyID})
	}
	return out
}

// A PLUGIN_TRUST_ADDED the agent wrote itself, for a key the trust store
// does not hold, is corrected at the next start with PLUGIN_TRUST_REMOVED,
// once. A PLUGIN_TRUST_REMOVED it wrote for a key the store holds is
// corrected with PLUGIN_TRUST_ADDED, and the entry that key signed is
// served throughout.
func TestForgedTrustEventIsCorrected(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	held, err := f.trust.AddedKeys()
	require.NoError(t, err)
	require.Len(t, held, 1)
	agentConn := l.dbs["product_a"].db

	require.NoError(t, guard.RecordPluginTrustAdded(context.Background(), agentConn, forgedKey), "the agent's role can write it")
	for range 2 {
		l.record(t, f, f.plugins(nil))
	}
	require.Equal(t, [][2]string{
		{"PLUGIN_TRUST_ADDED", held[0]}, {"PLUGIN_TRUST_ADDED", forgedKey}, {"PLUGIN_TRUST_REMOVED", forgedKey},
	}, l.trustRows(t, "product_a"))
	recs, err := guard.ReadPluginRecords(context.Background(), agentConn)
	require.NoError(t, err)
	require.Equal(t, []string{held[0]}, recs.TrustKeys)

	require.NoError(t, guard.RecordPluginTrustRemoved(context.Background(), agentConn, held[0]))
	ep := f.plugins(nil)
	l.record(t, f, ep)
	rows := l.trustRows(t, "product_a")
	require.Equal(t, [2]string{"PLUGIN_TRUST_ADDED", held[0]}, rows[len(rows)-1], "the held key is recorded again")
	require.Empty(t, ep.unrecordedFor(p.Key(), "product_a"), "its entry is served")
	require.Equal(t, [][2]string{{"PLUGIN_TRUST_ADDED", held[0]}}, l.trustRows(t, "client_x"), "the other agent's ledger is untouched")
}

// On a guard at schema version 3, which refuses PLUGIN_TRUST_REMOVED, the
// forged record stays, the failure is only logged, and every entry is
// served as before.
func TestTrustRemovedOnVersion3IsOnlyLogged(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	require.NoError(t, guard.RecordPluginTrustAdded(context.Background(), l.dbs["product_a"].db, forgedKey))
	ep := f.plugins(nil)
	// The guard refuses the kind as version 3's record_plugin_event does.
	v3 := map[string]pluginLedger{
		"product_a": {db: refuseKind{Querier: l.dbs["product_a"].db, kind: guard.PluginTrustRemoved}},
		"client_x":  l.dbs["client_x"],
	}
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, v3, slog.New(slog.DiscardHandler))
	require.Empty(t, ep.unrecordedFor(p.Key(), "product_a"))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))
}

// When the trust store cannot be read, no trust event is written, and an
// entry whose added key the ledger does not record yet is withheld; once
// the ledger records the key, its entry is served.
func TestUnreadTrustStoreWithholdsUnrecordedKeys(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	discard := slog.New(slog.DiscardHandler)
	ep := f.plugins(nil)
	got := withheldBy(context.Background(), wantedPlugins(f.cfg, ep, trustWant{}), l.dbs, discard)
	require.Equal(t, map[string][]unrecordedEntry{"product_a": {{key: p.Key(), why: whyTrustUnread}}}, got)
	require.Empty(t, l.events(t, "product_a"))

	l.record(t, f, f.plugins(nil))
	got = withheldBy(context.Background(), wantedPlugins(f.cfg, f.plugins(nil), trustWant{}), l.dbs, discard)
	require.Empty(t, got, "the ledger records the key: served")
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")), "nothing removed")
}

// A key on record whose entry was verified at start, but which the trust
// store no longer holds when the events are written, is recorded removed and
// its entry withheld, with that reason.
func TestKeyGoneFromTheStoreWithholdsItsEntry(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	ep := f.plugins(nil) // verified while the key is held
	key := l.trustRows(t, "product_a")[0][1]

	discard := slog.New(slog.DiscardHandler)
	got := withheldBy(context.Background(), wantedPlugins(f.cfg, ep, trustWant{read: true}), l.dbs, discard)
	require.Equal(t, []unrecordedEntry{{key: p.Key(), why: whyKeyNotTrusted}}, got["product_a"])
	rows := l.trustRows(t, "product_a")
	require.Equal(t, [2]string{"PLUGIN_TRUST_REMOVED", key}, rows[len(rows)-1])
}
