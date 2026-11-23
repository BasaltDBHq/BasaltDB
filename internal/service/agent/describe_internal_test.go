package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/piidict"
)

// fakeCatalog is a Catalog over fixed relations and details.
type fakeCatalog struct {
	visible    []CatalogRelation
	notGranted int
	details    map[uint32]CatalogDetail
	matches    []CatalogMatch
	lines      []string
	// guarded are the tables basalt init guards.
	guarded map[uint32]bool
	// searched records the exclude list of the last search.
	searched []CatalogColumnKey
}

func (f *fakeCatalog) Relations(context.Context) ([]CatalogRelation, int, error) {
	return f.visible, f.notGranted, nil
}

func (f *fakeCatalog) Find(_ context.Context, schema, name string) (CatalogRelation, bool, error) {
	for _, r := range f.visible {
		if r.Schema == schema && r.Name == name {
			return r, true, nil
		}
	}
	return CatalogRelation{}, false, nil
}

func (f *fakeCatalog) Describe(_ context.Context, oid uint32) (CatalogDetail, error) {
	return f.details[oid], nil
}

func (f *fakeCatalog) Guarded(_ context.Context, oid uint32) (bool, error) {
	return f.guarded[oid], nil
}

func (f *fakeCatalog) Search(_ context.Context, _ string, exclude []CatalogColumnKey, after *CatalogSearchCursor, limit int) ([]CatalogMatch, error) {
	f.searched = exclude
	out := []CatalogMatch{}
	for _, m := range f.matches {
		if after != nil && (m.Rank < after.Rank || (m.Rank == after.Rank && m.Schema+"."+m.Name <= after.Schema+"."+after.Name)) {
			continue
		}
		out = append(out, m)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeCatalog) Structure(context.Context) ([]string, error) { return f.lines, nil }
func (f *fakeCatalog) Database() string                            { return "app" }
func (f *fakeCatalog) Host() string                                { return "db.example.com" }
func (f *fakeCatalog) Limits() action.Limits                       { return action.Limits(sqlguard.DefaultLimits()) }

// fakeClasses is a ClassResolver over a fixed class map.
type fakeClasses struct {
	classes map[piidict.ColumnRef]piidict.Class
	print   string
}

func (f fakeClasses) Resolve(_ context.Context, refs []piidict.ColumnRef) ([]piidict.Class, error) {
	out := make([]piidict.Class, len(refs))
	for i, r := range refs {
		c, ok := f.classes[r]
		if !ok {
			c = piidict.Unclassified
		}
		out[i] = c
	}
	return out, nil
}

func (f fakeClasses) Secrets(context.Context) ([]piidict.ColumnRef, error) {
	var out []piidict.ColumnRef
	for r, c := range f.classes {
		if c.Class == guardmodel.ClassSecret {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f fakeClasses) CatalogFingerprint(context.Context) (string, error) { return f.print, nil }

const ordersOID = 100

func rel(oid uint32, schema, name string, privs ...string) CatalogRelation {
	rows := int64(12)
	if len(privs) == 0 {
		privs = []string{"SELECT"}
	}
	return CatalogRelation{OID: oid, Schema: schema, Name: name, Kind: "TABLE", EstimatedRows: &rows, Privileges: privs}
}

// ordersDetail is a table with a SECRET column (card_token), an ungranted
// one (cost_price), an index and a partial index on them, and a generated
// column over one of them.
func ordersDetail() CatalogDetail {
	d := CatalogDetail{CatalogRelation: rel(ordersOID, "shop", "orders", "SELECT", "UPDATE")}
	d.Columns = []CatalogColumn{
		{Attnum: 1, Name: "id", Type: "bigint", Selectable: true, Comment: "order id"},
		{Attnum: 2, Name: "card_token", Type: "text", Nullable: true, Selectable: true},
		{Attnum: 3, Name: "cost_price", Type: "numeric", Nullable: true},
		{
			Attnum: 4, Name: "margin", Type: "numeric", Nullable: true, Selectable: true, Generated: true,
			Default: "(price - cost_price)", DefaultAttnums: []int16{3, 5},
		},
		{Attnum: 5, Name: "price", Type: "numeric", Selectable: true, Default: "0"},
	}
	d.PrimaryKey = []int16{1}
	d.Indexes = []CatalogIndex{
		{Name: "orders_pkey", Definition: "CREATE UNIQUE INDEX orders_pkey ON shop.orders USING btree (id)", Attnums: []int16{1}, Unique: true},
		{Name: "orders_card_idx", Definition: "CREATE INDEX orders_card_idx ON shop.orders USING btree (card_token)", Attnums: []int16{2}},
		{Name: "orders_cheap_idx", Definition: "CREATE INDEX orders_cheap_idx ON shop.orders USING btree (price) WHERE cost_price < 1", Attnums: []int16{3, 5}, Partial: true},
	}
	d.Keys = []CatalogKey{
		{
			Name: "lines_order_fk", Attnums: []int16{1}, OtherOID: 101, OtherSchema: "shop", OtherTable: "lines",
			OtherColumns: []string{"order_id"}, OtherReadable: true, OnDelete: "CASCADE", OnUpdate: "NO ACTION",
		},
		{Name: "audit_fk", Attnums: []int16{1}, OtherOID: 102, OnDelete: "SET NULL", OnUpdate: "NO ACTION"},
		{
			Name: "card_fk", Outgoing: true, Attnums: []int16{2}, OtherOID: 101, OtherSchema: "shop", OtherTable: "lines",
			OtherColumns: []string{"token"}, OtherReadable: true, OnDelete: "RESTRICT", OnUpdate: "RESTRICT",
		},
	}
	d.Stats = CatalogStats{TableBytes: 8192, TotalBytes: 32768, SeqScans: 3}
	d.CascadesIntoHidden = 1
	return d
}

func describeService(t *testing.T, cat Catalog, classes fakeClasses, operatedBy string) *Service {
	t.Helper()
	d := deps()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	d.Status.OperatedBy = operatedBy
	d.Describe.Catalog = cat
	d.Describe.Classes = classes
	return NewService(d)
}

func ordersCatalog() (*fakeCatalog, fakeClasses) {
	cat := &fakeCatalog{
		visible: []CatalogRelation{rel(ordersOID, "shop", "orders", "SELECT", "UPDATE"), rel(101, "shop", "lines")},
		details: map[uint32]CatalogDetail{ordersOID: ordersDetail()},
		lines:   []string{"shop.orders:TABLE"},
		guarded: map[uint32]bool{ordersOID: true},
	}
	classes := fakeClasses{classes: map[piidict.ColumnRef]piidict.Class{
		{TableOID: ordersOID, Attnum: 1}: {Class: guardmodel.ClassPublic},
		{TableOID: ordersOID, Attnum: 2}: {Class: guardmodel.ClassSecret},
		{TableOID: ordersOID, Attnum: 5}: {Class: guardmodel.ClassPublic},
	}, print: "abc"}
	return cat, classes
}

// call runs one describe call through the tool's handler, as the agent
// would, and returns the JSON it gets: the result or the error body.
func callDescribe(t *testing.T, s *Service, args map[string]any) (string, bool) {
	t.Helper()
	var describe Tool
	for _, tool := range Tools(s) {
		if tool.Name == toolDescribe {
			describe = tool
		}
	}
	require.NotNil(t, describe.Call, "describe is served")
	raw, err := json.Marshal(args)
	require.NoError(t, err)
	out, err := describe.Call(context.Background(), raw)
	if err != nil {
		var te *toolresult.ToolError
		require.ErrorAs(t, err, &te)
		body, mErr := json.Marshal(te)
		require.NoError(t, mErr)
		return string(body), true
	}
	body, err := json.Marshal(out)
	require.NoError(t, err)
	return string(body), false
}

func decodeBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	return m
}

func stepKinds(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["nextSteps"].([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		st, ok := r.(map[string]any)
		require.True(t, ok)
		out = append(out, fmt.Sprintf("%s %s", st["actor"], st["action"]))
	}
	return out
}

func TestHideColumnsDropsIndexesKeysAndExpressions(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	s := describeService(t, cat, classes, "")
	body, isError := callDescribe(t, s, map[string]any{"resource": "shop.orders"})
	require.False(t, isError, body)

	for _, hidden := range []string{"card_token", "cost_price", "orders_card_idx", "orders_cheap_idx", "card_fk", "audit"} {
		require.NotContains(t, body, hidden)
	}
	m := decodeBody(t, body)
	require.Equal(t, "RESOURCE", m["form"])
	require.EqualValues(t, 2, m["hiddenFields"])
	require.EqualValues(t, 2, m["hiddenIndexes"])
	require.EqualValues(t, 0, m["hiddenKeys"])
	require.EqualValues(t, 2, m["hiddenForeignKeys"], "the key on a SECRET column and the one to an unreadable table")
	require.EqualValues(t, 1, m["cascadesIntoHidden"])
	require.Equal(t, []any{"id"}, m["primaryKey"])

	fields := m["fields"].([]any)
	require.Len(t, fields, 3)
	margin := fields[1].(map[string]any)
	require.Equal(t, "margin", margin["name"])
	require.Equal(t, true, margin["expressionHidden"])
	require.Nil(t, margin["default"])
	require.Contains(t, margin, "default", "default is null, not absent")
	price := fields[2].(map[string]any)
	require.Equal(t, "0", price["default"])
	require.Equal(t, map[string]any{"class": "PUBLIC"}, price["pii"])
	require.Equal(t, map[string]any{"class": "UNCLASSIFIED"}, margin["pii"])

	fks := m["foreignKeys"].([]any)
	require.Equal(t, []any{map[string]any{
		"direction": "INCOMING", "columns": []any{"id"}, "table": "shop.lines",
		"onDelete": "CASCADE", "onUpdate": "NO_ACTION",
	}}, fks)
	require.Equal(t, []any{"SELECT", "UPDATE"}, m["actions"])
	require.NotNil(t, m["policy"])
	require.Equal(t, map[string]any{
		"estimatedRows": 12.0, "tableBytes": 8192.0, "totalBytes": 32768.0,
		"seqScans": 3.0, "indexScans": 0.0, "lastAnalyzed": nil,
	}, m["stats"])
}

func TestHideColumnsDropsAPrimaryKeyOnAHiddenColumn(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	d := cat.details[ordersOID]
	d.PrimaryKey = []int16{1, 3}
	cat.details[ordersOID] = d
	body, isError := callDescribe(t, describeService(t, cat, classes, ""), map[string]any{"resource": "shop.orders"})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.NotContains(t, m, "primaryKey")
	require.EqualValues(t, 1, m["hiddenKeys"])
}

// TestReadOnlyTableHasNullPolicy: a guarded table the agent only reads has
// no write policy.
func TestReadOnlyTableHasNullPolicy(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	d := cat.details[ordersOID]
	d.Privileges = []string{"SELECT"}
	cat.details[ordersOID] = d
	body, isError := callDescribe(t, describeService(t, cat, classes, ""), map[string]any{"resource": "shop.orders"})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.Contains(t, m, "policy")
	require.Nil(t, m["policy"])
}

// TestUnguardedWritableTableHasNullPolicy: the write policy is the guard's,
// so a table the agent can write outside basalt init has none.
func TestUnguardedWritableTableHasNullPolicy(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	cat.guarded = nil
	body, isError := callDescribe(t, describeService(t, cat, classes, ""), map[string]any{"resource": "shop.orders"})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.Equal(t, []any{"SELECT", "UPDATE"}, m["actions"])
	require.Contains(t, m, "policy")
	require.Nil(t, m["policy"])
}

func manyRelations(n int) []CatalogRelation {
	out := make([]CatalogRelation, 0, n)
	for i := range n {
		schema := "app"
		if i%3 == 0 {
			schema = "billing"
		}
		out = append(out, rel(uint32(1000+i), schema, fmt.Sprintf("t%03d", i)))
	}
	// Ordered by schema and name, as Relations lists them.
	sort.Slice(out, func(i, j int) bool { return out[i].Schema+"."+out[i].Name < out[j].Schema+"."+out[j].Name })
	return out
}

func TestOverviewSmallListsResources(t *testing.T) {
	t.Parallel()
	cat := &fakeCatalog{visible: manyRelations(50)}
	body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, ""), map[string]any{})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.Equal(t, "OVERVIEW", m["form"])
	require.Len(t, m["resources"], 50)
	require.NotContains(t, m, "schemas")
	require.NotContains(t, m, "nextSteps")
	require.NotContains(t, m, "personMessage")
	require.Equal(t, map[string]any{"schemas": 2.0, "tables": 50.0, "notGranted": 0.0}, m["counts"])
	require.Equal(t, map[string]any{"kind": "POSTGRES", "database": "app", "host": "db.example.com"}, m["store"])
	first := m["resources"].([]any)[0].(map[string]any)
	require.Equal(t, map[string]any{"resource": "app.t001", "kind": "TABLE", "estimatedRows": 12.0, "access": []any{"SELECT"}}, first)
	limits := m["limits"].(map[string]any)
	require.EqualValues(t, sqlguard.DefaultReadRowLimit, limits["readRowLimit"])
	require.EqualValues(t, sqlguard.DefaultStatementTimeout.Milliseconds(), limits["statementTimeoutMs"])
	require.Equal(t, map[string]any{
		"allowedUpTo": 10.0, "heldUpTo": 50.0, "refusedOver": 50.0, "deleteHeld": true,
		"cascadedRowsCounted": true,
	}, limits["writePolicy"])
	require.Regexp(t, `^[0-9a-f]{64}$`, m["fingerprint"])
}

func TestOverviewLargeListsSchemas(t *testing.T) {
	t.Parallel()
	cat := &fakeCatalog{visible: manyRelations(51)}
	body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, ""), map[string]any{})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.NotContains(t, m, "resources")
	require.Equal(t, []any{
		map[string]any{"schema": "app", "tables": 34.0},
		map[string]any{"schema": "billing", "tables": 17.0},
	}, m["schemas"])
	require.Equal(t, []string{"AGENT CALL_TOOL"}, stepKinds(t, m))
	step := m["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, toolDescribe, step["tool"])
	require.Equal(t, map[string]any{"query": "app"}, step["arguments"], "the largest schema")
}

func TestOverviewNotGrantedHasNoAskPerson(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{mcpcontract.OperatedByPerson, mcpcontract.OperatedByAgent} {
		cat := &fakeCatalog{visible: manyRelations(3), notGranted: 3}
		body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, operatedBy), map[string]any{})
		require.False(t, isError, body)
		m := decodeBody(t, body)
		require.Equal(t, []string{"PERSON TELL_AGENT"}, stepKinds(t, m), operatedBy)
		require.NotContains(t, m["personMessage"], "basalt ", "the person runs no command")
		require.Contains(t, m["personMessage"], "3", operatedBy)
		require.Contains(t, m["personMessage"], "a link where you pick the tables", operatedBy)
		require.EqualValues(t, 3, m["counts"].(map[string]any)["notGranted"])
	}
}

func TestOverviewLargeAndNotGrantedCarriesBoth(t *testing.T) {
	t.Parallel()
	cat := &fakeCatalog{visible: manyRelations(60), notGranted: 1}
	body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, ""), map[string]any{})
	require.False(t, isError, body)
	require.Equal(t, []string{"AGENT CALL_TOOL", "PERSON TELL_AGENT"}, stepKinds(t, decodeBody(t, body)))
}

func TestOverviewFingerprintFollowsStructureGrantsAndPII(t *testing.T) {
	t.Parallel()
	fp := func(cat *fakeCatalog, classes fakeClasses) string {
		body, isError := callDescribe(t, describeService(t, cat, classes, ""), map[string]any{})
		require.False(t, isError, body)
		return decodeBody(t, body)["fingerprint"].(string)
	}
	base := fp(&fakeCatalog{visible: manyRelations(2), lines: []string{"a"}}, fakeClasses{})
	require.Equal(t, base, fp(&fakeCatalog{visible: manyRelations(2), lines: []string{"a"}}, fakeClasses{}))
	require.NotEqual(t, base, fp(&fakeCatalog{visible: manyRelations(2), lines: []string{"a", "b"}}, fakeClasses{}))
	require.NotEqual(t, base, fp(&fakeCatalog{visible: manyRelations(2), lines: []string{"a"}, notGranted: 1}, fakeClasses{}))
	require.NotEqual(t, base, fp(&fakeCatalog{visible: manyRelations(2), lines: []string{"a"}}, fakeClasses{print: "x"}))
}

func TestDescribeNotFoundSameForAbsentAndHidden(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{mcpcontract.OperatedByPerson, mcpcontract.OperatedByAgent} {
		// shop.secret exists but is not granted: the catalog does not find it,
		// exactly as it does not find a table that does not exist.
		cat := &fakeCatalog{visible: manyRelations(2), notGranted: 1}
		s := describeService(t, cat, fakeClasses{}, operatedBy)
		hidden, isError := callDescribe(t, s, map[string]any{"resource": "shop.secret"})
		require.True(t, isError)
		absent, isError := callDescribe(t, s, map[string]any{"resource": "shop.nosuch"})
		require.True(t, isError)
		require.Equal(t, strings.ReplaceAll(hidden, "secret", "nosuch"), absent, "only the echoed name differs")

		m := decodeBody(t, absent)
		require.Equal(t, CodeNotFound, m["code"])
		require.Equal(t, []string{"AGENT CALL_TOOL", "AGENT ASK_PERSON", "PERSON TELL_AGENT", "AGENT RUN_COMMAND"}, stepKinds(t, m), operatedBy)
		steps := m["nextSteps"].([]any)
		require.Equal(t, map[string]any{"query": "nosuch"}, steps[0].(map[string]any)["arguments"])
		want := "basalt init --agent bot"
		if operatedBy == mcpcontract.OperatedByAgent {
			want += " --remote"
		}
		require.Equal(t, want, steps[3].(map[string]any)["command"])
		require.NotContains(t, m["personMessage"], "basalt ", "the person runs no command")
	}
}

func TestResourceFingerprintIgnoresStats(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	s := describeService(t, cat, classes, "")
	first := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))

	d := cat.details[ordersOID]
	d.Stats.SeqScans, d.Stats.TotalBytes = 99, 1<<20
	rows := int64(5000)
	d.EstimatedRows = &rows
	cat.details[ordersOID] = d
	second := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))
	require.NotEqual(t, first["stats"], second["stats"])
	require.Equal(t, first["fingerprint"], second["fingerprint"], "stats are left out")

	d.Indexes[0].Scans, d.Indexes[0].SizeBytes = 1234, 1<<20
	cat.details[ordersOID] = d
	scanned := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))
	require.NotEqual(t, first["indexes"], scanned["indexes"])
	require.Equal(t, first["fingerprint"], scanned["fingerprint"], "index sizes and scans are left out")

	d.Columns[0].Comment = "the order's id"
	cat.details[ordersOID] = d
	third := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))
	require.NotEqual(t, first["fingerprint"], third["fingerprint"])

	classes.print = "reclassified"
	fourth := decodeBody(t, mustDescribe(t, describeService(t, cat, classes, ""), map[string]any{"resource": "shop.orders"}))
	require.NotEqual(t, third["fingerprint"], fourth["fingerprint"], "the PII catalog fingerprint is mixed in")
}

func mustDescribe(t *testing.T, s *Service, args map[string]any) string {
	t.Helper()
	body, isError := callDescribe(t, s, args)
	require.False(t, isError, body)
	return body
}

func TestIfFingerprintUnchanged(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	s := describeService(t, cat, classes, "")
	full := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))
	fp := full["fingerprint"].(string)

	same := mustDescribe(t, s, map[string]any{"resource": "shop.orders", "ifFingerprint": fp})
	require.JSONEq(t, fmt.Sprintf(`{"form":"RESOURCE","resource":"shop.orders","fingerprint":%q,"unchanged":true}`, fp), same)

	stale := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders", "ifFingerprint": "0000"}))
	require.NotContains(t, stale, "unchanged")
	require.Contains(t, stale, "fields")
}

func TestDescribeRejectsQueryAndResourceTogether(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	s := describeService(t, cat, classes, "")
	for _, args := range []map[string]any{
		{"query": "orders", "resource": "shop.orders"},
		{"query": ""},
		{"query": strings.Repeat("x", 101)},
		{"resource": "orders"},
		{"resource": "shop.orders.x"},
		{"resource": `"shop.orders`},
		{"ifFingerprint": "abc"},
		{"limit": 5},
		{"query": "orders", "ifFingerprint": "abc"},
		{"query": "orders", "sort": "name"},
		{"resource": "shop.orders", "cursor": "x"},
		{"unknown": true},
	} {
		body, isError := callDescribe(t, s, args)
		require.True(t, isError, "%v: %s", args, body)
		m := decodeBody(t, body)
		require.Equal(t, CodeInvalidArgument, m["code"], "%v", args)
		require.Equal(t, []string{"AGENT REVISE_CALL"}, stepKinds(t, m), "%v", args)
	}
}

func TestDescribeStaleCursor(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	body, isError := callDescribe(t, describeService(t, cat, classes, ""), map[string]any{"query": "orders", "cursor": "not-a-cursor"})
	require.True(t, isError)
	m := decodeBody(t, body)
	require.Equal(t, CodeInvalidArgument, m["code"])
	require.Equal(t, ReasonStaleCursor, m["reason"])
}

func TestDescribeQuotedResourceNames(t *testing.T) {
	t.Parallel()
	cat := &fakeCatalog{visible: []CatalogRelation{rel(7, "Sales", "Order Items"), rel(8, "public", "order"), rel(9, "public", "leads")}}
	cat.details = map[uint32]CatalogDetail{
		7: {CatalogRelation: cat.visible[0]}, 8: {CatalogRelation: cat.visible[1]}, 9: {CatalogRelation: cat.visible[2]},
	}
	s := describeService(t, cat, fakeClasses{}, "")
	for in, printed := range map[string]string{
		`"Sales"."Order Items"`: `"Sales"."Order Items"`,
		`public."order"`:        `public."order"`,
		`Public.Leads`:          `public.leads`,
		`"public"."leads"`:      `public.leads`,
	} {
		m := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": in}))
		require.Equal(t, printed, m["resource"], in)
	}
}

func TestCommentTrimmed(t *testing.T) {
	t.Parallel()
	long := "  " + strings.Repeat("é", 600) + "  "
	d := ordersDetail()
	d.Comment = long
	r := d.CatalogRelation
	cat := &fakeCatalog{
		visible: []CatalogRelation{r},
		details: map[uint32]CatalogDetail{ordersOID: d},
		matches: []CatalogMatch{{CatalogRelation: r, Rank: 0, Matched: "table"}},
	}
	_, classes := ordersCatalog()
	s := describeService(t, cat, classes, "")

	res := decodeBody(t, mustDescribe(t, s, map[string]any{"resource": "shop.orders"}))
	require.Equal(t, strings.Repeat("é", 500), res["comment"])

	found := decodeBody(t, mustDescribe(t, s, map[string]any{"query": "orders"}))
	item := found["items"].([]any)[0].(map[string]any)
	require.Equal(t, strings.Repeat("é", 120), item["comment"])
	require.Equal(t, "table", item["matched"])
}

func TestDescribeSearchPagesAndExcludesSecrets(t *testing.T) {
	t.Parallel()
	cat, classes := ordersCatalog()
	for _, r := range manyRelations(5) {
		cat.matches = append(cat.matches, CatalogMatch{CatalogRelation: r, Rank: 2, Matched: "table"})
	}
	sort.Slice(cat.matches, func(i, j int) bool {
		return cat.matches[i].Schema+"."+cat.matches[i].Name < cat.matches[j].Schema+"."+cat.matches[j].Name
	})
	s := describeService(t, cat, classes, "")
	first := decodeBody(t, mustDescribe(t, s, map[string]any{"query": "t", "limit": 3}))
	require.Equal(t, "SEARCH", first["form"])
	require.Len(t, first["items"], 3)
	require.NotEmpty(t, first["nextCursor"])
	require.Equal(t, []CatalogColumnKey{{OID: ordersOID, Attnum: 2}}, cat.searched, "SECRET columns are excluded")

	next := decodeBody(t, mustDescribe(t, s, map[string]any{"query": "t", "limit": 3, "cursor": first["nextCursor"]}))
	require.NotContains(t, next, "nextCursor", "the last page")
	require.NotEmpty(t, next["items"])
}

// outputSchema is describe's output schema with its local $refs inlined; a
// reference to another file (nextSteps, links) is checked by the catalog
// tests and accepted here.
func outputSchema(t *testing.T) map[string]any {
	t.Helper()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), toolDescribe)
	require.True(t, ok)
	raw, err := json.Marshal(tool.OutputSchema)
	require.NoError(t, err)
	var schema map[string]any
	require.NoError(t, json.Unmarshal(raw, &schema))
	defs, _ := schema["$defs"].(map[string]any)
	resolved, _ := inlineRefs(schema, defs).(map[string]any)
	return resolved
}

func inlineRefs(node any, defs map[string]any) any {
	switch x := node.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			if name, local := strings.CutPrefix(ref, "#/$defs/"); local {
				return inlineRefs(defs[name], defs)
			}
			return map[string]any{}
		}
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = inlineRefs(v, defs)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = inlineRefs(v, defs)
		}
		return out
	}
	return node
}

// TestDescribeAnswersMatchTheOutputSchema: every form the engine answers
// validates against the contract's output schema.
func TestDescribeAnswersMatchTheOutputSchema(t *testing.T) {
	t.Parallel()
	schema := outputSchema(t)
	cat, classes := ordersCatalog()
	cat.visible = append(cat.visible, manyRelations(60)...)
	cat.notGranted = 2
	cat.matches = []CatalogMatch{{CatalogRelation: cat.visible[0], Rank: 1, Matched: "column id"}}
	large := describeService(t, cat, classes, "")
	small := describeService(t, &fakeCatalog{visible: manyRelations(3)}, fakeClasses{}, "")
	fp := decodeBody(t, mustDescribe(t, large, map[string]any{"resource": "shop.orders"}))["fingerprint"]
	for name, c := range map[string]struct {
		s    *Service
		args map[string]any
	}{
		"overview large": {large, map[string]any{}},
		"overview small": {small, map[string]any{}},
		"search":         {large, map[string]any{"query": "id", "limit": 1}},
		"resource":       {large, map[string]any{"resource": "shop.orders"}},
		"unchanged":      {large, map[string]any{"resource": "shop.orders", "ifFingerprint": fp}},
	} {
		body := decodeBody(t, mustDescribe(t, c.s, c.args))
		require.NoError(t, validateSchema(schema, body), "%s: %v", name, body)
	}
	// The check is live: an unknown field, a bad enum or a long comment fails.
	require.Error(t, validateSchema(schema, map[string]any{"form": "OVERVIEW", "tables": 1.0}))
	require.Error(t, validateSchema(schema, map[string]any{"form": "RESOURCE", "kind": "INDEX"}))
	require.Error(t, validateSchema(schema, map[string]any{"form": "RESOURCE", "comment": strings.Repeat("x", 501)}))
}

// errCatalog is a Catalog whose every read fails with err.
type errCatalog struct {
	fakeCatalog
	err error
}

func (e *errCatalog) Relations(context.Context) ([]CatalogRelation, int, error) {
	return nil, 0, e.err
}

func (e *errCatalog) Find(context.Context, string, string) (CatalogRelation, bool, error) {
	return CatalogRelation{}, false, e.err
}

func (e *errCatalog) Search(context.Context, string, []CatalogColumnKey, *CatalogSearchCursor, int) ([]CatalogMatch, error) {
	return nil, e.err
}

// TestDescribeErrorsStayInTheContract: describe declares INVALID_ARGUMENT,
// NOT_FOUND, QUERY_TIMEOUT, UNAVAILABLE and INTERNAL only, so any other
// Postgres error reading the catalog is INTERNAL, never SQL_ERROR or
// PERMISSION_DENIED; a timeout stays QUERY_TIMEOUT with a step that fits the
// form, and an unreachable database stays UNAVAILABLE.
func TestDescribeErrorsStayInTheContract(t *testing.T) {
	t.Parallel()
	forms := map[string]map[string]any{
		"overview": {}, "search": {"query": "orders"}, "resource": {"resource": "shop.orders"},
	}
	for name, args := range forms {
		for _, c := range []struct {
			err  error
			code string
		}{
			{store.MapError(&pgconn.PgError{Code: "42501", Message: "permission denied for table pg_class"}), CodeInternal},
			{store.MapError(&pgconn.PgError{Code: "42703", Message: `column "x" does not exist`}), CodeInternal},
			{store.MapError(&pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"}), CodeQueryTimeout},
			{store.MapError(&pgconn.PgError{Code: "08006", Message: "connection failure"}), CodeUnavailable},
			{errors.New("boom"), CodeInternal},
		} {
			s := describeService(t, &errCatalog{err: c.err}, fakeClasses{}, "")
			body, isError := callDescribe(t, s, args)
			require.True(t, isError, "%s: %v", name, c.err)
			m := decodeBody(t, body)
			require.Equal(t, c.code, m["code"], "%s: %v", name, c.err)
			require.NotEmpty(t, m["nextSteps"], "%s: %v", name, c.err)
			require.NotContains(t, body, "pg_class", "an engine failure names nothing")
			if c.code == CodeQueryTimeout {
				text := m["nextSteps"].([]any)[0].(map[string]any)["text"].(string)
				require.NotContains(t, text, "statement", "%s: the step fits describe", name)
				if name == "search" {
					require.Contains(t, text, "more specific query")
				}
			}
		}
	}
}

// TestDescribeWithoutClassesFailsClosed: with no PII classes the engine
// cannot tell SECRET columns, so describe answers INTERNAL instead of
// showing every column.
func TestDescribeWithoutClassesFailsClosed(t *testing.T) {
	t.Parallel()
	cat, _ := ordersCatalog()
	d := deps()
	d.Describe.Catalog = cat
	s := NewService(d)
	for _, args := range []map[string]any{{}, {"query": "orders"}, {"resource": "shop.orders"}} {
		body, isError := callDescribe(t, s, args)
		require.True(t, isError, "%v", args)
		require.Equal(t, CodeInternal, decodeBody(t, body)["code"], "%v", args)
		require.NotContains(t, body, "card_token")
	}
}

// TestParseResource: an unquoted name folds to lower case as Postgres folds
// it, ASCII A to Z only; a quoted one is kept as written.
func TestParseResource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, schema, name string }{
		{"shop.orders", "shop", "orders"},
		{"Shop.ORDERS", "shop", "orders"},
		{`"Sales"."Order Items"`, "Sales", "Order Items"},
		{`"a""b".t`, `a"b`, "t"},
		{"Café.Ärger", "café", "Ärger"}, // non-ASCII letters keep their case
	} {
		schema, name, err := parseResource(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, []string{tc.schema, tc.name}, []string{schema, name}, tc.in)
	}
	for _, bad := range []string{"orders", `"shop.orders`, `"".t`, "a b.t", "a.b.c"} {
		_, _, err := parseResource(bad)
		require.Error(t, err, bad)
	}
}

// manySchemas is one table in each of n schemas, plus extra tables in the
// schemas named by bigger.
func manySchemas(n int, bigger map[string]int) []CatalogRelation {
	var out []CatalogRelation
	oid := uint32(1000)
	add := func(schema string, tables int) {
		for i := range tables {
			oid++
			out = append(out, rel(oid, schema, fmt.Sprintf("t%d", i)))
		}
	}
	for i := range n {
		name := fmt.Sprintf("tenant_%05d", i)
		add(name, 1+bigger[name])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Schema+"."+out[i].Name < out[j].Schema+"."+out[j].Name })
	return out
}

func TestOverviewCapsTheSchemaList(t *testing.T) {
	t.Parallel()
	// 5,000 schemas; tenant_00007 has 9 tables, tenant_04999 has 5, the
	// rest one each.
	cat := &fakeCatalog{visible: manySchemas(5000, map[string]int{"tenant_00007": 8, "tenant_04999": 4})}
	body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, ""), map[string]any{})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	schemas := m["schemas"].([]any)
	require.Len(t, schemas, 50)
	require.Equal(t, map[string]any{"schema": "tenant_00007", "tables": 9.0}, schemas[0])
	require.Equal(t, map[string]any{"schema": "tenant_04999", "tables": 5.0}, schemas[1])
	require.Equal(t, map[string]any{"schema": "tenant_00000", "tables": 1.0}, schemas[2], "ties by schema name")
	require.Equal(t, map[string]any{"schema": "tenant_00048", "tables": 1.0}, schemas[49])
	require.Equal(t, map[string]any{"schemas": 4950.0, "tables": 4950.0}, m["otherSchemas"])
	require.Equal(t, 5000.0, m["counts"].(map[string]any)["schemas"], "the full count")
	require.Equal(t, 5012.0, m["counts"].(map[string]any)["tables"])
	step := m["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, map[string]any{"query": "tenant_00007"}, step["arguments"], "the largest schema")
	require.Less(t, len(body), 8<<10, "the answer stays small")
}

func TestOverviewWithFiftySchemasHasNoOtherSchemas(t *testing.T) {
	t.Parallel()
	cat := &fakeCatalog{visible: manySchemas(50, map[string]int{"tenant_00003": 1})}
	body, isError := callDescribe(t, describeService(t, cat, fakeClasses{}, ""), map[string]any{})
	require.False(t, isError, body)
	m := decodeBody(t, body)
	require.Len(t, m["schemas"], 50)
	require.NotContains(t, m, "otherSchemas")
}

func TestDescribeNotFoundHintsAtAnotherAgent(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "/etc/basalt-test/engine.json", "linux", testManager())
	require.NoError(t, err)
	s := &Service{deps: Deps{Core: CoreDeps{Commands: cmds}}}
	msg := s.describeNotFoundSteps(NewSteps(), failure{tool: toolDescribe})
	require.Contains(t, msg, "another database needs its own agent")
	require.NotContains(t, msg, "basalt ", "the person runs no command")
	require.NoError(t, CheckPersonMessage(msg))
}
