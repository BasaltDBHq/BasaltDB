package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/testkit/agenttest"

	"github.com/basaltdbhq/basaltdb/internal/app"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// describeSQL is the describe fixture: a quoted schema and table, orders
// with a SECRET column (card_token), a column the agent is not granted
// (cost_price), an index and a partial index on them and a generated column
// over one, lines the agent writes, and audit, which it cannot read and
// which a delete of an order cascades into.
const describeSQL = `
CREATE SCHEMA shop;
CREATE SCHEMA "Sales";
CREATE TABLE "Sales"."Order Items" (id bigint PRIMARY KEY, sku text NOT NULL);
COMMENT ON TABLE "Sales"."Order Items" IS 'Line items, one per product in an order';
CREATE TABLE shop.orders (
    id         bigint PRIMARY KEY,
    card_token text,
    cost_price numeric,
    price      numeric NOT NULL DEFAULT 0,
    margin     numeric GENERATED ALWAYS AS (price - cost_price) STORED,
    status     text NOT NULL DEFAULT 'new'
);
COMMENT ON TABLE shop.orders IS 'Customer orders';
COMMENT ON COLUMN shop.orders.status IS 'new, paid or shipped';
CREATE INDEX orders_card_idx ON shop.orders (card_token);
CREATE INDEX orders_cheap_idx ON shop.orders (price) WHERE cost_price < 1;
CREATE INDEX orders_status_idx ON shop.orders (status);
CREATE TABLE shop.lines (
    id       bigint PRIMARY KEY,
    order_id bigint NOT NULL REFERENCES shop.orders ON DELETE CASCADE,
    qty      int NOT NULL
);
CREATE TABLE shop.audit (id bigint PRIMARY KEY, order_id bigint REFERENCES shop.orders ON DELETE CASCADE);
INSERT INTO shop.orders (id, card_token, cost_price, price) SELECT g, 'tok' || g, 1, 10 FROM generate_series(1, 20) g;
INSERT INTO shop.lines SELECT g, g, 1 FROM generate_series(1, 20) g;
ANALYZE shop.orders, shop.lines, shop.audit, "Sales"."Order Items";
`

// hiddenNames must never appear in any describe answer.
var hiddenNames = []string{"card_token", "cost_price", "orders_card_idx", "orders_cheap_idx", "audit", "tok1"}

type describeHarness struct {
	harness
	db   *guardtest.DB
	role string
}

func describeDB(t *testing.T) describeHarness { return describeDBWithUpdate(t, nil) }

// describeDBWithUpdate is describeDB for an engine whose update check
// answers with update.
func describeDBWithUpdate(t *testing.T, update func() *agent.UpdateNotice) describeHarness {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, describeSQL)
	a := d.NewAgent(t, "bot", []string{"shop.lines"}, []string{"shop.orders"})
	role := pgx.Identifier{a.Role}.Sanitize()
	d.Exec(t, `REVOKE SELECT ON shop.orders FROM `+role+`;
		GRANT SELECT (id, card_token, price, margin, status) ON shop.orders TO `+role+`;
		GRANT USAGE ON SCHEMA "Sales" TO `+role+`;
		GRANT SELECT ON "Sales"."Order Items" TO `+role)
	classifyDescribe(t, d)

	svc := agenttest.PgService(t, a.URL, agenttest.WithDeps(func(d *agent.Deps, pool *pgxpool.Pool) {
		d.Describe.Catalog = app.NewAgentCatalog(store.NewCatalog(pool, sqlguard.DefaultLimits(), pool.Config().ConnConfig.Database).WithHost("db.example.com"))
		d.Describe.Classes = pii.NewMap(slog.New(slog.DiscardHandler)).On(pool)
		d.Status.Update = update
	})).Svc
	return describeHarness{harness: harness{server: mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(agent.Tools(svc), agent.WithMeta)...)}, db: d, role: a.Role}
}

// classifyDescribe classes every readable column PUBLIC and card_token
// SECRET, as basalt classify would record it.
func classifyDescribe(t *testing.T, d *guardtest.DB) {
	t.Helper()
	ctx := context.Background()
	rows, err := d.Admin.Query(ctx, `SELECT table_schema, table_name, column_name, data_type FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.PIIColumn, error) {
		var c guardmodel.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guardmodel.ClassPublic
		if c.Column == "card_token" {
			c.Class = guardmodel.ClassSecret
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(ctx, tx, d.Names, guardmodel.Classification{Columns: cols, At: time.Now()})
	}))
}

// describe calls the tool and returns the answer, after checking it names
// nothing the agent cannot read.
func (h describeHarness) describe(t *testing.T, args map[string]any) (map[string]any, bool) {
	t.Helper()
	body, isError := h.call(t, "describe", args)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	asked := fmt.Sprint(args)
	for _, name := range hiddenNames {
		if strings.Contains(asked, name) {
			continue // the agent's own words are echoed back
		}
		require.NotContains(t, string(raw), name, "a hidden name in the answer to %v", args)
	}
	return body, isError
}

func TestDescribeQuotedIdentifiers(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	found, isError := h.describe(t, map[string]any{"query": "order items"})
	require.False(t, isError, "%v", found)
	list := items(t, found)
	require.NotEmpty(t, list)
	require.Equal(t, `"Sales"."Order Items"`, list[0]["resource"])

	res, isError := h.describe(t, map[string]any{"resource": list[0]["resource"]})
	require.False(t, isError, "%v", res)
	require.Equal(t, `"Sales"."Order Items"`, res["resource"])
	require.Equal(t, "Line items, one per product in an order", res["comment"])
}

func TestDescribeHidesWhatTheAgentCannotRead(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	res, isError := h.describe(t, map[string]any{"resource": "shop.orders"})
	require.False(t, isError, "%v", res)
	require.Equal(t, json.Number("2"), res["hiddenFields"])
	require.Equal(t, json.Number("2"), res["hiddenIndexes"])
	require.Equal(t, json.Number("1"), res["hiddenForeignKeys"])
	require.Equal(t, json.Number("1"), res["cascadesIntoHidden"])

	for _, q := range []string{"card", "cost", "audit", "tok"} {
		found, isError := h.describe(t, map[string]any{"query": q})
		require.False(t, isError, "%v", found)
		for _, it := range items(t, found) {
			require.NotEqual(t, "shop.orders", it["resource"], "%s matched only a hidden column", q)
		}
	}

	body, isError := h.describe(t, map[string]any{"resource": "shop.audit"})
	require.True(t, isError)
	requireToolError(t, body, isError, guidance.CodeNotFound, "", "")
	absent, _ := h.describe(t, map[string]any{"resource": "shop.nosuch"})
	hiddenRaw, err := json.Marshal(body)
	require.NoError(t, err)
	absentRaw, err := json.Marshal(absent)
	require.NoError(t, err)
	require.Equal(t, strings.ReplaceAll(string(hiddenRaw), "audit", "nosuch"), string(absentRaw),
		"absent and unreadable get the same answer")
}

// TestDescribePolicyOnlyOnGuardedTables: the write policy is the guard's,
// so a table the agent was granted INSERT on outside basalt init has none,
// and a table init guards for writes keeps it.
func TestDescribePolicyOnlyOnGuardedTables(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	role := pgx.Identifier{h.role}.Sanitize()
	h.db.Exec(t, `CREATE TABLE shop.notes (id bigint PRIMARY KEY, body text);
		GRANT SELECT, INSERT ON shop.notes TO `+role)

	notes, isError := h.describe(t, map[string]any{"resource": "shop.notes"})
	require.False(t, isError, "%v", notes)
	require.Equal(t, []any{"SELECT", "INSERT"}, notes["actions"])
	require.Contains(t, notes, "policy")
	require.Nil(t, notes["policy"], "an unguarded table has no write policy")

	lines, isError := h.describe(t, map[string]any{"resource": "shop.lines"})
	require.False(t, isError, "%v", lines)
	require.NotNil(t, lines["policy"], "a guarded writable table has the write policy")

	// A guard from before agent_guarded_tables guards nothing describe can
	// report: no policy, and no error.
	h.db.Exec(t, `DROP VIEW basalt_meta.agent_guarded_tables CASCADE`)
	lines, isError = h.describe(t, map[string]any{"resource": "shop.lines"})
	require.False(t, isError, "%v", lines)
	require.Contains(t, lines, "policy")
	require.Nil(t, lines["policy"])
}

func TestDescribeIfFingerprint(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	res, isError := h.describe(t, map[string]any{"resource": "shop.orders"})
	require.False(t, isError, "%v", res)
	fp := str(t, res["fingerprint"])

	// Rows that grow the indexes, and an index scan the statistics count.
	h.db.Exec(t, `INSERT INTO shop.orders (id, price) SELECT g, 5 FROM generate_series(100, 3000) g; ANALYZE shop.orders`)
	h.db.Exec(t, `SET enable_seqscan = off`)
	h.db.Exec(t, `SELECT id FROM shop.orders WHERE status = 'new'`)
	h.db.Exec(t, `RESET enable_seqscan`)
	require.Eventually(t, func() bool {
		var scans int64
		err := h.db.Admin.QueryRow(context.Background(), `SELECT coalesce(sum(idx_scan), 0) FROM pg_stat_user_indexes
			WHERE relname = 'orders'`).Scan(&scans)
		return err == nil && scans > 0
	}, 10*time.Second, 100*time.Millisecond, "the index scan reaches the statistics")
	moved, isError := h.describe(t, map[string]any{"resource": "shop.orders"})
	require.False(t, isError, "%v", moved)
	require.NotEqual(t, res["indexes"], moved["indexes"], "index sizes or scans moved")
	same, isError := h.describe(t, map[string]any{"resource": "shop.orders", "ifFingerprint": fp})
	require.False(t, isError, "%v", same)
	require.Equal(t, map[string]any{"form": "RESOURCE", "resource": "shop.orders", "fingerprint": fp, "unchanged": true}, same,
		"row counts, index sizes and scans do not change the fingerprint")

	h.db.Exec(t, `ALTER TABLE shop.orders ADD COLUMN note text`)
	changed, isError := h.describe(t, map[string]any{"resource": "shop.orders", "ifFingerprint": fp})
	require.False(t, isError, "%v", changed)
	require.NotContains(t, changed, "unchanged")
	require.NotEqual(t, fp, changed["fingerprint"])
}

func TestDescribeOverviewFingerprintFollowsStructure(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	first, isError := h.describe(t, map[string]any{})
	require.False(t, isError, "%v", first)
	h.db.Exec(t, `INSERT INTO shop.lines VALUES (100, 1, 2); ANALYZE shop.lines`)
	second, _ := h.describe(t, map[string]any{})
	require.Equal(t, first["fingerprint"], second["fingerprint"], "rows do not move it")
	h.db.Exec(t, `CREATE INDEX lines_qty_idx ON shop.lines (qty)`)
	third, _ := h.describe(t, map[string]any{})
	require.NotEqual(t, first["fingerprint"], third["fingerprint"], "an index does")

	h.db.Exec(t, `GRANT INSERT ON shop.orders TO `+pgx.Identifier{h.role}.Sanitize())
	granted, _ := h.describe(t, map[string]any{})
	require.NotEqual(t, third["fingerprint"], granted["fingerprint"], "a write grant does")

	h.db.Exec(t, `COMMENT ON TABLE shop.lines IS 'Order lines'`)
	commented, _ := h.describe(t, map[string]any{})
	require.NotEqual(t, granted["fingerprint"], commented["fingerprint"], "a table comment does")
}

// TestDescribeDoesNotRecordReads: describe reads the catalog only, so the
// ledger gets no row for any form (CONTRACT.md, describe, Recording).
func TestDescribeDoesNotRecordReads(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	count := func() int {
		var n int
		require.NoError(t, h.db.Admin.QueryRow(context.Background(), `SELECT count(*) FROM basalt_meta.ledger`).Scan(&n))
		return n
	}
	before := count()
	for _, args := range []map[string]any{{}, {"query": "orders"}, {"resource": "shop.orders"}, {"resource": "shop.nosuch"}} {
		h.describe(t, args)
		require.Equal(t, before, count(), "%v", args)
	}
}

func TestDescribeServedGolden(t *testing.T) {
	t.Parallel()
	h := describeDB(t)
	for _, c := range []struct {
		name    string
		args    map[string]any
		isError bool
	}{
		{"overview", map[string]any{}, false},
		{"search", map[string]any{"query": "order"}, false},
		{"resource", map[string]any{"resource": "shop.orders"}, false},
		{"not_found", map[string]any{"resource": "shop.audit"}, true},
	} {
		body, isError := h.describe(t, c.args)
		require.Equal(t, c.isError, isError, "%s: %v", c.name, body)
		requireGolden(t, c.name, body)
	}
}

// TestDescribeSearchScale is the 5,000-table measurement (design: "Search
// on thousands of tables must answer within" the statement timeout). Opt-in:
// BASALTDB_TEST_SCALE=1.
func TestDescribeSearchScale(t *testing.T) {
	if os.Getenv("BASALTDB_TEST_SCALE") != "1" {
		t.Skip("BASALTDB_TEST_SCALE=1 runs the 5,000-table measurement")
	}
	// batch tables per statement string: one implicit transaction each, so
	// the locks fit in max_locks_per_transaction.
	const tables, columns, batch = 5000, 20, 200
	d := guardtest.New(t)
	d.Exec(t, "CREATE SCHEMA big")
	var ddl bytes.Buffer
	for i := range tables {
		fmt.Fprintf(&ddl, "CREATE TABLE big.t%04d (id bigint PRIMARY KEY", i)
		for c := 1; c < columns; c++ {
			fmt.Fprintf(&ddl, ", c%02d_t%04d text", c, i)
		}
		ddl.WriteString(");\n")
		if (i+1)%batch == 0 {
			d.Exec(t, ddl.String())
			ddl.Reset()
		}
	}
	d.Exec(t, `CREATE TABLE public.anchor (id bigint PRIMARY KEY)`)
	a := d.NewAgent(t, "bot", []string{"public.anchor"}, nil)
	d.Exec(t, `GRANT USAGE ON SCHEMA big TO `+pgx.Identifier{a.Role}.Sanitize()+`;
		GRANT SELECT ON ALL TABLES IN SCHEMA big TO `+pgx.Identifier{a.Role}.Sanitize())

	svc := agenttest.PgService(t, a.URL, agenttest.WithDeps(func(d *agent.Deps, pool *pgxpool.Pool) {
		d.Describe.Catalog = app.NewAgentCatalog(store.NewCatalog(pool, sqlguard.DefaultLimits(), pool.Config().ConnConfig.Database).WithHost("db.example.com"))
		d.Describe.Classes = pii.NewMap(slog.New(slog.DiscardHandler)).On(pool)
	})).Svc
	h := harness{server: mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(agent.Tools(svc), agent.WithMeta)...)}
	h.call(t, "describe", map[string]any{"resource": "public.anchor"}) // warm the pool and the class map

	measure := func(name string, args map[string]any) {
		start := time.Now()
		body, isError := h.call(t, "describe", args)
		took := time.Since(start)
		require.False(t, isError, "%s: %v", name, body)
		t.Logf("%s: %s", name, took)
		require.Less(t, took, sqlguard.DefaultLimits().StatementTimeout, name)
	}
	measure("overview", map[string]any{})
	measure("search table prefix", map[string]any{"query": "t04"})
	measure("search column", map[string]any{"query": "c19_t4999"})
	measure("search no match", map[string]any{"query": "zzzz"})
	measure("search page 200", map[string]any{"query": "t", "limit": 200})
	measure("resource", map[string]any{"resource": "big.t2500"})
}

// TestDescribeOverviewScaleSchemas is the one-schema-per-tenant measurement
// (D-3): 5,000 schemas with one table each. The overview lists 50 schemas,
// counts the rest, is small and answers within the statement timeout.
// Opt-in: BASALTDB_TEST_SCALE=1.
func TestDescribeOverviewScaleSchemas(t *testing.T) {
	if os.Getenv("BASALTDB_TEST_SCALE") != "1" {
		t.Skip("BASALTDB_TEST_SCALE=1 runs the 5,000-schema measurement")
	}
	const schemas = 5000
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.anchor (id bigint PRIMARY KEY)`)
	a := d.NewAgent(t, "bot", []string{"public.anchor"}, nil)
	role := pgx.Identifier{a.Role}.Sanitize()
	// One statement per 250 schemas: the locks fit in max_locks_per_transaction.
	for from := 0; from < schemas; from += 250 {
		d.Exec(t, fmt.Sprintf(`DO $$ BEGIN
			FOR i IN %d..%d LOOP
				EXECUTE format('CREATE SCHEMA %%I', 'tenant_' || lpad(i::text, 5, '0'));
				EXECUTE format('CREATE TABLE %%I.accounts (id bigint PRIMARY KEY, name text)', 'tenant_' || lpad(i::text, 5, '0'));
				EXECUTE format('GRANT USAGE ON SCHEMA %%I TO %s', 'tenant_' || lpad(i::text, 5, '0'));
				EXECUTE format('GRANT SELECT ON %%I.accounts TO %s', 'tenant_' || lpad(i::text, 5, '0'));
			END LOOP; END $$`, from, from+249, role, role))
	}

	svc := agenttest.PgService(t, a.URL, agenttest.WithDeps(func(d *agent.Deps, pool *pgxpool.Pool) {
		d.Describe.Catalog = app.NewAgentCatalog(store.NewCatalog(pool, sqlguard.DefaultLimits(), pool.Config().ConnConfig.Database).WithHost("db.example.com"))
		d.Describe.Classes = pii.NewMap(slog.New(slog.DiscardHandler)).On(pool)
	})).Svc
	h := harness{server: mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(agent.Tools(svc), agent.WithMeta)...)}
	h.call(t, "describe", map[string]any{"resource": "public.anchor"}) // warm the pool and the class map

	start := time.Now()
	body, isError := h.call(t, "describe", map[string]any{})
	took := time.Since(start)
	require.False(t, isError, "%v", body)
	t.Logf("overview of %d schemas: %s", schemas, took)
	require.Less(t, took, sqlguard.DefaultLimits().StatementTimeout)
	require.Len(t, body["schemas"], 50)
	n, err := body["counts"].(map[string]any)["schemas"].(json.Number).Int64()
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(schemas), "counts.schemas is the full number")
	require.NotNil(t, body["otherSchemas"])
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.Less(t, len(raw), 16<<10, "the overview stays small")
}

// TestDescribeOverviewCarriesTheUpdate: the overview form, and only it,
// carries the engine's newer-release notice (CONTRACT.md, Update notice).
func TestDescribeOverviewCarriesTheUpdate(t *testing.T) {
	t.Parallel()
	h := describeDBWithUpdate(t, func() *agent.UpdateNotice {
		return &agent.UpdateNotice{Current: "0.0.1", Latest: "0.0.2", Security: true, URL: "https://example.test/r"}
	})
	overview, isError := h.describe(t, map[string]any{})
	require.False(t, isError, "%v", overview)
	u, ok := overview["update"].(map[string]any)
	require.True(t, ok, "update in %v", overview)
	require.Equal(t, "0.0.2", u["latest"])
	require.Equal(t, true, u["security"])
	require.Contains(t, u["message"], "SECURITY UPDATE: ")

	plain := describeDB(t)
	none, _ := plain.describe(t, map[string]any{})
	require.NotContains(t, none, "update", "no notice, no field")
}
