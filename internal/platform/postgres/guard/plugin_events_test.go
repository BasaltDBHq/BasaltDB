package guard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// eventExamples are the plugin event examples of the contract
// (api/plugin/testdata/{valid,invalid}-event-*.json).
func eventExamples(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "api", "plugin", "testdata", "*-event-*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		out[filepath.Base(f)] = b
	}
	return out
}

// recordRaw calls record_plugin_event as the agent with a raw kind and
// detail, as an agent role could on its own connection.
func recordRaw(t *testing.T, q guard.Querier, kind string, detail string) error {
	t.Helper()
	// Plain SQL: the guard function called with raw input, as an agent could.
	_, err := q.Exec(context.Background(), `SELECT basalt_meta.record_plugin_event($1, $2::jsonb)`, kind, detail)
	return err
}

// validLocal is a PLUGIN_ENABLED detail of a local entry in same-user mode.
func validLocal() guardmodel.PluginDetail {
	return guardmodel.PluginDetail{
		Name: "acme-ner", Instance: "default", Version: "1.4.0",
		ManifestSHA256: strings.Repeat("3f", 32), SignerKeyID: "jNZPxNG5htlwfhg4ZgknAA",
		Hooks: []string{"wire.detect"}, Roles: []string{"VALUE"}, Egress: []string{},
		Endpoint:  guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointLocal},
		Isolation: &guardmodel.PluginIsolation{Files: guardmodel.PluginFilesNone, Network: guardmodel.PluginNetworkNotEnforced},
	}
}

func pluginEvents(t *testing.T, d *guardtest.DB, role string) int {
	t.Helper()
	return count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE agent = $1 AND kind LIKE 'PLUGIN\_%'`, role)
}

// The guard accepts exactly the contract's examples: every valid event is
// appended, every invalid one is refused with BS008 and writes nothing.
func TestPluginEventSchemaExamples(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	valid := 0
	for name, raw := range eventExamples(t) {
		var ev struct {
			Kind   string          `json:"kind"`
			Detail json.RawMessage `json:"detail"`
		}
		require.NoError(t, json.Unmarshal(raw, &ev), name)
		err := recordRaw(t, a.Conn, ev.Kind, string(ev.Detail))
		if strings.HasPrefix(name, "valid-") {
			require.NoError(t, err, name)
			valid++
			continue
		}
		requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	}
	require.Equal(t, valid, pluginEvents(t, d, a.Role))
}

// A detail key outside the contract is refused, whatever it would carry:
// another agent's name, a config value, a path.
func TestUnknownDetailKeyRefused(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	base, err := json.Marshal(validLocal())
	require.NoError(t, err)
	for _, extra := range []string{
		`"agents": ["other"]`, `"config": {"languages": ["en"]}`, `"credentialFile": "/etc/x"`, `"note": "x"`,
	} {
		detail := strings.TrimSuffix(string(base), "}") + "," + extra + "}"
		requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginEnabled), detail), guardmodel.CodeLedgerInputInvalid)
	}
	for _, detail := range []string{
		`{"signerKeyId": "jNZPxNG5htlwfhg4ZgknAA", "name": "acme-ner"}`,
		`{"signerKeyId": "jNZPxNG5htlwfhg4ZgknAA", "agent": "other"}`,
	} {
		requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginTrustAdded), detail), guardmodel.CodeLedgerInputInvalid)
	}
	require.Zero(t, pluginEvents(t, d, a.Role))
}

// Every nested shape is checked, not only the top-level keys.
func TestPluginEventShapesRefused(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	remote := validLocal()
	remote.Isolation, remote.Endpoint = nil, guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointRemote, Host: "ner.acme.example:443"}
	remote.Egress = []string{"ner.acme.example:443", "[::1]:8443", "10.0.0.1:443"}
	for name, mutate := range map[string]func(m map[string]any){
		"no name":                 func(m map[string]any) { delete(m, "name") },
		"name not a plugin name":  func(m map[string]any) { m["name"] = "Other Agent" },
		"instance not a name":     func(m map[string]any) { m["instance"] = "client x" },
		"version free text":       func(m map[string]any) { m["version"] = "1.0.0 used by other-agent" },
		"version too long":        func(m map[string]any) { m["version"] = "1.0.0-" + strings.Repeat("a", 64) },
		"sha256 upper case":       func(m map[string]any) { m["manifestSha256"] = strings.Repeat("3F", 32) },
		"signer not a key id":     func(m map[string]any) { m["signerKeyId"] = "acme-2026" },
		"no hooks":                func(m map[string]any) { m["hooks"] = []string{} },
		"unknown hook":            func(m map[string]any) { m["hooks"] = []string{"wire.verdict"} },
		"hook twice":              func(m map[string]any) { m["hooks"] = []string{"wire.detect", "wire.detect"} },
		"hooks not an array":      func(m map[string]any) { m["hooks"] = "wire.detect" },
		"roles without detect":    func(m map[string]any) { m["hooks"] = []string{"feed.observe"} },
		"unknown role":            func(m map[string]any) { m["roles"] = []string{"OTHER"} },
		"roles null":              func(m map[string]any) { m["roles"] = nil },
		"egress missing":          func(m map[string]any) { delete(m, "egress") },
		"egress not host:port":    func(m map[string]any) { m["egress"] = []string{"https://x.example"} },
		"egress twice":            func(m map[string]any) { m["egress"] = []string{"x.example:443", "x.example:443"} },
		"egress a number":         func(m map[string]any) { m["egress"] = []any{443} },
		"endpoint kind unknown":   func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "ELSEWHERE"} },
		"local with a host":       func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "LOCAL", "host": "x.example:443"} },
		"endpoint extra key":      func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "LOCAL", "path": "/opt/x"} },
		"local without isolation": func(m map[string]any) { delete(m, "isolation") },
		"isolation extra key": func(m map[string]any) {
			m["isolation"] = map[string]any{"files": "NONE", "network": "NOT_ENFORCED", "user": "x"}
		},
		"isolation files unknown":   func(m map[string]any) { m["isolation"] = map[string]any{"files": "ROOT", "network": "ENFORCED"} },
		"isolation network missing": func(m map[string]any) { m["isolation"] = map[string]any{"files": "NONE"} },
		"endpoint an array":         func(m map[string]any) { m["endpoint"] = []any{"LOCAL"} },
		"isolation an array":        func(m map[string]any) { m["isolation"] = []any{"NONE"} },
		"model an array":            func(m map[string]any) { m["model"] = []any{"m"} },
		"model free text":           func(m map[string]any) { m["model"] = map[string]any{"name": "a model", "version": "1"} },
		"model extra key": func(m map[string]any) {
			m["model"] = map[string]any{"name": "m", "version": "1", "path": "x"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginChanged), mutated(t, validLocal(), mutate)), guardmodel.CodeLedgerInputInvalid)
		})
	}
	for name, mutate := range map[string]func(m map[string]any){
		"remote without host":    func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "REMOTE"} },
		"remote host a url":      func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "REMOTE", "host": "https://x.example"} },
		"remote with isolation":  func(m map[string]any) { m["isolation"] = map[string]any{"files": "NONE", "network": "NOT_ENFORCED"} },
		"remote host not string": func(m map[string]any) { m["endpoint"] = map[string]any{"kind": "REMOTE", "host": 443} },
	} {
		t.Run(name, func(t *testing.T) {
			requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginChanged), mutated(t, remote, mutate)), guardmodel.CodeLedgerInputInvalid)
		})
	}
	for _, detail := range []string{`null`, `[]`, `"x"`, `{}`} {
		requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginDisabled), detail), guardmodel.CodeLedgerInputInvalid)
	}
	requireCode(t, recordRaw(t, a.Conn, "PLUGIN_INSTALLED", mutated(t, validLocal(), nil)), guardmodel.CodeLedgerInputInvalid)
	requireCode(t, recordRaw(t, a.Conn, "HEARTBEAT", mutated(t, validLocal(), nil)), guardmodel.CodeLedgerInputInvalid)
	require.Zero(t, pluginEvents(t, d, a.Role))

	// The shapes above are refused for their one change: the bases pass.
	require.NoError(t, recordRaw(t, a.Conn, string(guardmodel.PluginChanged), mutated(t, validLocal(), nil)))
	require.NoError(t, recordRaw(t, a.Conn, string(guardmodel.PluginChanged), mutated(t, remote, nil)))
}

func mutated(t *testing.T, d guardmodel.PluginDetail, mutate func(map[string]any)) string {
	t.Helper()
	b, err := json.Marshal(d)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	if mutate != nil {
		mutate(m)
	}
	b, err = json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

// A detail over 4 KiB is refused with BS008, even when every key is one
// the contract allows.
func TestPluginEventOver4KiBRefused(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	big := validLocal()
	for i := range 250 {
		big.Egress = append(big.Egress, fmt.Sprintf("host%03d.example:443", i))
	}
	b, err := json.Marshal(big)
	require.NoError(t, err)
	require.Greater(t, len(b), 4096)
	err = guard.RecordPluginEntryEvent(context.Background(), a.Conn, guardmodel.PluginEnabled, big)
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	require.Equal(t, "BS008", guardtest.SQLState(err))
	require.Zero(t, pluginEvents(t, d, a.Role))
}

// Plugin events are chained like every other row: the chain verifies after
// them, and from a pin taken before them.
func TestPluginEventsKeepTheChain(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	pin, err := guardtest.Head(ctx, a.Conn)
	require.NoError(t, err)
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, validLocal()))
	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, "jNZPxNG5htlwfhg4ZgknAA"))
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginDisabled, validLocal()))
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
	st, _, err = guard.VerifyChainFrom(ctx, a.Conn, pin)
	require.NoError(t, err)
	require.True(t, st.Intact)
}

// Two agents on one database: each event goes to the caller's own ledger
// (session_user, never an argument), and each reads only its own.
func TestPluginEventsAreEachAgentsOwn(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "helper", leads, nil)
	ctx := context.Background()
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, validLocal()))
	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, "jNZPxNG5htlwfhg4ZgknAA"))
	require.Equal(t, 2, pluginEvents(t, d, a.Role))
	require.Zero(t, pluginEvents(t, d, b.Role))

	own, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.PluginDetail{validLocal()}, own.EnabledPlugins())
	require.Equal(t, []guardmodel.PluginTrustEvent{{KeyID: "jNZPxNG5htlwfhg4ZgknAA", Kind: guardmodel.PluginTrustAdded}}, own.LatestTrustEvents)
	other, err := guard.ReadPluginRecords(ctx, b.Conn)
	require.NoError(t, err)
	require.Empty(t, other.Entries)
	require.Empty(t, other.LatestTrustEvents)

	// The admin (not an agent role) cannot write one at all.
	requireCode(t, recordRaw(t, d.Admin, string(guardmodel.PluginEnabled), mutated(t, validLocal(), nil)), guardmodel.CodeNotAllowed)
}

// The latest event of each entry decides: a disabled entry is not listed.
func TestReadPluginRecordsTakesTheLatest(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	one, two := validLocal(), validLocal()
	two.Instance = "client_x"
	changed := one
	changed.Version = "1.5.0"
	for _, ev := range []struct {
		kind guardmodel.PluginEventKind
		d    guardmodel.PluginDetail
	}{
		{guardmodel.PluginEnabled, one}, {guardmodel.PluginEnabled, two}, {guardmodel.PluginChanged, changed}, {guardmodel.PluginDisabled, two},
	} {
		require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, ev.kind, ev.d))
	}
	recs, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.Len(t, recs.Entries, 2)
	require.Equal(t, []guardmodel.PluginDetail{changed}, recs.EnabledPlugins())
}

// The migration's SQL runs again over itself without error, and the guard
// still records afterwards.
func TestPluginEventsMigrationIsIdempotent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	sql := guard.PluginEventsSQL(d.Names)
	for range 2 {
		d.Exec(t, "BEGIN; SET LOCAL ROLE "+d.Names.Guard()+"; SET LOCAL search_path = pg_catalog, pg_temp;"+sql+"COMMIT;")
	}
	require.NoError(t, guard.RecordPluginEntryEvent(context.Background(), a.Conn, guardmodel.PluginEnabled, validLocal()))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(oid)::int FROM pg_catalog.pg_proc
		WHERE proname = 'record_plugin_event' AND pronamespace = 'basalt_meta'::regnamespace`))
	var public bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT has_function_privilege('public', 'basalt_meta.record_plugin_event(text, jsonb)', 'EXECUTE')`).Scan(&public))
	require.False(t, public, "PUBLIC cannot run it")
}

// A guard at version 2 has no record_plugin_event, so an engine's write
// fails there (and the engine serves no plugin to that agent); the upgrade
// adds it and keeps the chain.
func TestPluginEventsUpgradeFromVersion2(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 2)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	require.Error(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, validLocal()))
	recs, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err, "reading needs no version 3")
	require.Empty(t, recs.Entries)

	restore()
	// Up to the version before StoreNeutralVersion: the chain does not
	// verify rows hashed before that version (clean state).
	guardtest.UpToVersion(t, guard.StoreNeutralVersion-1)
	d.NewAgent(t, "bot", leads, nil)
	require.NoError(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginEnabled, validLocal()))
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
}

// A key is trusted on the record when its latest PLUGIN_TRUST_ADDED or
// PLUGIN_TRUST_REMOVED is an ADDED: removed, it is not listed; added again,
// it is.
func TestReadPluginRecordsTakesTheLatestTrustEvent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	const k1, k2 = "jNZPxNG5htlwfhg4ZgknAA", "AAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, k1))
	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, k2))
	require.NoError(t, guard.RecordPluginTrustRemoved(ctx, a.Conn, k2))
	recs, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.ElementsMatch(t, []guardmodel.PluginTrustEvent{{KeyID: k2, Kind: guardmodel.PluginTrustRemoved}, {KeyID: k1, Kind: guardmodel.PluginTrustAdded}}, recs.LatestTrustEvents)

	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, k2))
	require.NoError(t, guard.RecordPluginTrustRemoved(ctx, a.Conn, k1))
	recs, err = guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.ElementsMatch(t, []guardmodel.PluginTrustEvent{{KeyID: k2, Kind: guardmodel.PluginTrustAdded}, {KeyID: k1, Kind: guardmodel.PluginTrustRemoved}}, recs.LatestTrustEvents)

	require.Error(t, guard.RecordPluginEntryEvent(ctx, a.Conn, guardmodel.PluginTrustRemoved, validLocal()), "a key event carries no entry")
	requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginTrustRemoved), `{"signerKeyId": "short"}`), guardmodel.CodeLedgerInputInvalid)
	requireCode(t, recordRaw(t, a.Conn, string(guardmodel.PluginTrustRemoved), mutated(t, validLocal(), nil)), guardmodel.CodeLedgerInputInvalid)
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
}

// A guard at version 3 refuses PLUGIN_TRUST_REMOVED until the upgrade;
// version 4's SQL then runs again over itself and keeps the function's
// grants.
func TestPluginTrustRemovedMigration(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, 3)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	requireCode(t, guard.RecordPluginTrustRemoved(ctx, a.Conn, "jNZPxNG5htlwfhg4ZgknAA"), guardmodel.CodeLedgerInputInvalid)
	require.NoError(t, guard.RecordPluginTrustAdded(ctx, a.Conn, "jNZPxNG5htlwfhg4ZgknAA"), "version 3 still records")

	restore()
	// Up to the version before StoreNeutralVersion: the chain does not
	// verify rows hashed before that version (clean state).
	guardtest.UpToVersion(t, guard.StoreNeutralVersion-1)
	d.NewAgent(t, "bot", leads, nil)
	sql := guard.PluginTrustRemovedSQL(d.Names)
	d.Exec(t, "BEGIN; SET LOCAL ROLE "+d.Names.Guard()+"; SET LOCAL search_path = pg_catalog, pg_temp;"+sql+"COMMIT;")
	require.NoError(t, guard.RecordPluginTrustRemoved(ctx, a.Conn, "jNZPxNG5htlwfhg4ZgknAA"))
	recs, err := guard.ReadPluginRecords(ctx, a.Conn)
	require.NoError(t, err)
	require.Equal(t, []guardmodel.PluginTrustEvent{{KeyID: "jNZPxNG5htlwfhg4ZgknAA", Kind: guardmodel.PluginTrustRemoved}}, recs.LatestTrustEvents)
	var public bool
	require.NoError(t, d.Admin.QueryRow(ctx,
		`SELECT has_function_privilege('public', 'basalt_meta.record_plugin_event(text, jsonb)', 'EXECUTE')`).Scan(&public))
	require.False(t, public, "PUBLIC cannot run it")
	requireCode(t, recordRaw(t, d.Admin, string(guardmodel.PluginTrustRemoved), `{"signerKeyId": "jNZPxNG5htlwfhg4ZgknAA"}`), guardmodel.CodeNotAllowed)
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.True(t, st.Intact)
}
