//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// pluginLedgers is a guard with the fixture's two agents, each with its own
// connection, as the engine holds them.
type pluginLedgers struct {
	d     *guardtest.DB
	roles map[string]string
	dbs   map[string]guard.Querier
}

func newPluginLedgers(t *testing.T, f *pluginFixture) pluginLedgers {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	l := pluginLedgers{d: d, roles: map[string]string{}, dbs: map[string]guard.Querier{}}
	for _, a := range f.cfg.Agents {
		ag := d.NewAgent(t, a.Name, demoTables, nil)
		l.roles[a.Name], l.dbs[a.Name] = ag.Role, ag.Conn
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
	want := wantedPlugins(f.cfg, ep, nil)
	discard := slog.New(slog.DiscardHandler)
	require.Empty(t, writePluginEvents(context.Background(), want, l.dbs, discard))
	d := want.served["product_a"][p.Key()]
	d.Egress = []string{"ner.acme.example:443"}
	want.served["product_a"][p.Key()] = d
	for range 2 {
		require.Empty(t, writePluginEvents(context.Background(), want, l.dbs, discard))
	}
	require.Equal(t, []string{"PLUGIN_ENABLED", "PLUGIN_CHANGED"}, kindsOf(l.events(t, "product_a")))
}

// An entry enabled and listed that the engine does not start (it fails
// verification) keeps its record: no PLUGIN_DISABLED for a passing failure.
func TestHeldEntryKeepsItsRecord(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	l := newPluginLedgers(t, f)
	l.record(t, f, f.plugins(nil))
	require.NoError(t, os.WriteFile(f.installedFile(p), []byte("changed"), 0o755))
	ep := f.plugins(nil)
	require.Equal(t, []string{agent.ProblemPluginNotTrusted}, codes(ep.PluginProblems("product_a")))
	l.record(t, f, ep)
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))
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
	broken := map[string]guard.Querier{"product_a": l.dbs["product_a"], "client_x": l.d.Admin} // not an agent role: refused
	ep := f.plugins(nil)
	recordPluginEvents(context.Background(), f.cfg, f.configPath, ep, broken, slog.New(slog.DiscardHandler))
	require.Empty(t, l.events(t, "client_x"))
	require.Equal(t, []string{"PLUGIN_TRUST_ADDED", "PLUGIN_ENABLED"}, kindsOf(l.events(t, "product_a")))

	runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	require.Empty(t, ep.PluginProblems("product_a"))
	probs := ep.PluginProblems("client_x")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(probs))
	require.Contains(t, probs[0].Message, "could not be written to this agent's ledger")
	require.NotContains(t, probs[0].Message, "product_a")
	err := ep.host.Call(context.Background(), p.Key(), []string{"client_x"}, protocol.MethodHealth, nil, nil)
	require.ErrorIs(t, err, plugin.ErrAgentNotListed, "the host refuses a call naming the withheld agent")

	// The only listed agent unrecorded: the entry does not start at all.
	solo := newPluginFixture(t)
	q := solo.install("default", dial.TransportStdio, "client_x")
	ep = solo.plugins(nil)
	recordPluginEvents(context.Background(), solo.cfg, solo.configPath, ep, map[string]guard.Querier{}, slog.New(slog.DiscardHandler))
	require.Empty(t, ep.entries)
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(ep.PluginProblems("client_x")))
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
		d := pluginDetail(k, plugin.Verified{Manifest: m, ManifestSHA256: sha, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA"}, plugin.ModeSameUser)
		for _, kind := range []guard.PluginEventKind{guard.PluginEnabled, guard.PluginDisabled, guard.PluginChanged} {
			b, err := json.Marshal(map[string]any{"kind": kind, "detail": d})
			require.NoError(t, err)
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			require.NoError(t, err)
			require.NoError(t, sch.Validate(inst), string(b))
		}
	}
	d := pluginDetail(k, plugin.Verified{Manifest: remote, ManifestSHA256: sha, SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA"}, plugin.ModeSameUser)
	require.Equal(t, guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: "ner.acme.example:443"}, d.Endpoint)
	require.Nil(t, d.Isolation, "a remote entry records no local isolation")
	require.Equal(t, []string{"approval.deliver", "feed.observe"}, d.Hooks)
}
