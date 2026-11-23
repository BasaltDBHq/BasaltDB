package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/testkit/agenttest"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// testDB creates a database with the guard installed (the Postgres
// container is shared, so names are unique per test) and a fixture the
// agent role can partly read: it reads leads and writes audit, and cannot
// touch secrets. It returns the admin URL of the database and the agent's
// URL.
func testDB(t *testing.T) (string, string) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `
		CREATE TABLE leads (
			id bigint PRIMARY KEY, name text, score numeric, ratio float8, ok bool,
			meta jsonb, created timestamptz, tags text[]
		);
		INSERT INTO leads VALUES
			(1, 'Ada', 12345678901234567890.123, 0.5, true, '{"src": "web"}', '2026-11-10T06:02:11Z', '{a,b}'),
			(2, NULL, NULL, 'NaN', false, NULL, NULL, NULL);
		CREATE TABLE secrets (id int PRIMARY KEY, body text);
		CREATE TABLE audit (id serial PRIMARY KEY, at timestamptz DEFAULT now());
		CREATE FUNCTION bump() RETURNS int LANGUAGE sql AS 'INSERT INTO audit DEFAULT VALUES RETURNING id';
	`)
	a := d.NewAgent(t, "bot", []string{"public.audit"}, []string{"public.leads"})
	return d.URL, a.URL
}

type harness struct {
	server *mcp.Server
	reader *store.Reader
}

func newHarness(t *testing.T, agentURL string, limits sqlguard.Limits) harness {
	t.Helper()
	return newHarnessConns(t, agentURL, limits, 2)
}

// newHarnessConns is newHarness with a pool of conns connections.
func newHarnessConns(t *testing.T, agentURL string, limits sqlguard.Limits, conns int32) harness {
	t.Helper()
	env := agenttest.PgService(t, agentURL, agenttest.WithLimits(limits), agenttest.WithConns(conns))
	return harness{
		server: mcp.NewServer(mcp.Info{Name: "basalt"}, mcp.ToolsFrom(agent.Tools(env.Svc), agent.WithMeta)...),
		reader: env.Reader,
	}
}

// query runs one query call.
func (h harness) query(t *testing.T, args any) (map[string]any, bool) {
	t.Helper()
	return h.call(t, "query", args)
}

// call runs one tools/call through the MCP server, as an agent would, and
// returns the decoded text body and isError.
func (h harness) call(t *testing.T, tool string, args any) (map[string]any, bool) {
	t.Helper()
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, h.server.Serve(context.Background(), bytes.NewReader(append(req, '\n')), &out))
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp), out.String())
	require.Len(t, resp.Result.Content, 1, out.String())
	var body map[string]any
	dec := json.NewDecoder(strings.NewReader(resp.Result.Content[0].Text))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&body), resp.Result.Content[0].Text)
	return body, resp.Result.IsError
}

func requireToolError(t *testing.T, body map[string]any, isError bool, code, reason, sqlState string) {
	t.Helper()
	require.True(t, isError, "%v", body)
	require.Equal(t, code, body["code"], "%v", body)
	if reason != "" {
		require.Equal(t, reason, body["reason"], "%v", body)
	}
	if sqlState != "" {
		require.Equal(t, sqlState, body["sqlState"], "%v", body)
	}
}

func TestQueryReturnsRowsAsJSON(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())

	body, isError := h.query(t, map[string]any{
		"sql":    "SELECT id, name, score, ratio, ok, meta, created, tags, lower(name) AS lname FROM leads WHERE id >= $1 ORDER BY id",
		"params": []any{1},
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, json.Number("2"), body["rowCount"])
	rows, ok := body["rows"].([]any)
	require.True(t, ok)
	first, ok := rows[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, json.Number("1"), first["id"])
	require.Equal(t, "Ada", first["name"])
	require.Equal(t, json.Number("12345678901234567890.123"), first["score"], "numeric keeps its precision")
	require.Equal(t, json.Number("0.5"), first["ratio"])
	require.Equal(t, true, first["ok"])
	require.Equal(t, map[string]any{"src": "web"}, first["meta"])
	require.Equal(t, "2026-11-10T06:02:11Z", first["created"])
	require.Equal(t, "{a,b}", first["tags"])
	require.Equal(t, "ada", first["lname"])

	second, ok := rows[1].(map[string]any)
	require.True(t, ok)
	require.Nil(t, second["name"])
	require.Nil(t, second["score"])
	require.Equal(t, "NaN", second["ratio"])
	require.Equal(t, false, second["ok"])

	cols, ok := body["columns"].([]any)
	require.True(t, ok)
	require.Len(t, cols, 9)
	require.Equal(t, map[string]any{"name": "score", "type": "numeric"}, cols[2])
}

func TestQueryKeepsRepeatedColumnNames(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())
	body, isError := h.query(t, map[string]any{"sql": "SELECT a.id, b.id FROM leads a JOIN leads b ON b.id = a.id WHERE a.id = 1"})
	require.False(t, isError, "%v", body)
	rows, ok := body["rows"].([]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"id": json.Number("1"), "id_2": json.Number("1")}, rows[0])
}

// TestQuerySizeLimit: a result that would cost the engine over 16 MiB is
// refused, and the agent's connections keep working after it: many rows
// together, or many small or NULL values, with SIZE_LIMIT; one row alone,
// whether its value is long or full of bytes JSON escapes, or over the
// connection's message cap, with ROW_TOO_LARGE naming its columns.
func TestQuerySizeLimit(t *testing.T) {
	t.Parallel()
	adminURL, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())
	admin, err := pgdial.Connect(context.Background(), adminURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	nulls := make([]string, 0, wideColumns)
	for i := range wideColumns {
		nulls = append(nulls, fmt.Sprintf("NULL c%d", i))
	}
	for name, c := range map[string]struct{ sql, reason, names string }{
		"many rows":   {"SELECT repeat('x', 1048576) FROM generate_series(1, 17) g", agent.ReasonSizeLimit, ""},
		"wide, NULLs": {"SELECT " + strings.Join(nulls, ", ") + " FROM generate_series(1, 1000) g", agent.ReasonSizeLimit, ""},
		"one value":   {"SELECT 1 AS id, repeat('x', 20000000) AS big", agent.ReasonRowTooLarge, "its columns: id, big (which is largest is unknown)"},
		// JSON escapes these, and the MCP text escapes the backslash again:
		// 2.7 million bytes make an 18 MiB line the shim would refuse.
		"control bytes":  {"SELECT 1 AS id, repeat(chr(1), 2700000) AS ctl", agent.ReasonRowTooLarge, "its largest columns: ctl (18.0 MiB), id (131 bytes)"},
		"angle brackets": {"SELECT repeat('<', 2700000) AS lt", agent.ReasonRowTooLarge, "its largest columns: lt (18.0 MiB)"},
	} {
		body, isError := h.query(t, map[string]any{"sql": c.sql})
		requireToolError(t, body, isError, agent.CodeQueryTimeout, c.reason, "")
		require.Contains(t, body["message"], c.names, name)
		var refused int
		require.NoError(t, admin.QueryRow(context.Background(),
			`SELECT count(change_id)::int FROM basalt_meta.changes
			 WHERE status = 'REFUSED' AND code = 'QUERY_TIMEOUT' AND statement = $1`, c.sql).Scan(&refused))
		require.Equal(t, 1, refused, "%s: the refused read is in the ledger", name)
		body, isError = h.query(t, map[string]any{"sql": "SELECT 1 AS one"})
		require.False(t, isError, "%s: the next query works: %v", name, body)
	}
	body, isError := h.query(t, map[string]any{"sql": "SELECT repeat('x', 1048576) FROM generate_series(1, 15) g"})
	require.False(t, isError, "15 MiB fits: %v", body)
}

// TestRowTooLargeStepsSaySliceOrSize: ROW_TOO_LARGE tells the agent to
// select fewer columns, a size or a slice, never a shortened value.
func TestRowTooLargeStepsSaySliceOrSize(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())
	body, isError := h.query(t, map[string]any{"sql": "SELECT repeat('<', 2700000) AS lt"})
	requireToolError(t, body, isError, agent.CodeQueryTimeout, agent.ReasonRowTooLarge, "")
	steps, ok := body["nextSteps"].([]any)
	require.True(t, ok, "%v", body)
	require.Len(t, steps, 1)
	step, ok := steps[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "REVISE_CALL", step["action"])
	require.Contains(t, step["text"], "length(col)")
	require.Contains(t, step["text"], "substr(col, 1, 100000)")
}

// wideColumns is enough NULL columns that 1000 rows of them pass 16 MiB
// in what they cost, with 0 bytes of values, in a statement under the
// query tool's 16 KiB.
const wideColumns = 300

// TestOneValueOverTheMessageCapIsNeverRead: pgx refuses a row message over
// the agent connection's cap before it reads the body (MaxProtocolMessageBodyLen),
// so the engine never buffers the value; the row is too large, with its
// size on the wire.
func TestOneValueOverTheMessageCapIsNeverRead(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	r := agenttest.PgService(t, agentURL, agenttest.WithConns(1)).Reader
	_, err := r.Read(context.Background(), "SELECT repeat('x', 20000000) AS big", nil, action.Statement{})
	var tooLarge *resultsize.RowTooLargeError
	require.ErrorAs(t, err, &tooLarge)
	require.True(t, tooLarge.OnWire)
	require.Greater(t, tooLarge.Bytes, budget.MaxBytes)
	require.Equal(t, []resultsize.ColumnSize{{Name: "big", Bytes: -1}}, tooLarge.Columns)
}

func TestQueryLimits(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.Limits{StatementTimeout: 200 * time.Millisecond, ReadRowLimit: 5})

	body, isError := h.query(t, map[string]any{"sql": "SELECT g FROM generate_series(1, 5) g"})
	require.False(t, isError, "%v", body)
	require.Equal(t, json.Number("5"), body["rowCount"])

	body, isError = h.query(t, map[string]any{"sql": "SELECT g FROM generate_series(1, 1000) g"})
	requireToolError(t, body, isError, agent.CodeQueryTimeout, agent.ReasonRowLimit, "")

	start := time.Now()
	body, isError = h.query(t, map[string]any{"sql": "SELECT count(g) FROM generate_series(1, 1000000000) g"})
	requireToolError(t, body, isError, agent.CodeQueryTimeout, agent.ReasonTimeLimit, "57014")
	require.Less(t, time.Since(start), 5*time.Second)

	// The pool still works after a canceled statement.
	body, isError = h.query(t, map[string]any{"sql": "SELECT 1 AS one"})
	require.False(t, isError, "%v", body)
}

func TestQueryErrors(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())

	cases := []struct {
		name                   string
		args                   map[string]any
		code, reason, sqlState string
	}{
		{"ungranted table", map[string]any{"sql": "SELECT * FROM secrets"}, agent.CodePermissionDenied, "", "42501"},
		{"unknown column", map[string]any{"sql": "SELECT nope FROM leads"}, agent.CodeSQLError, "", "42703"},
		{"write sent to query", map[string]any{"sql": "DELETE FROM leads"}, agent.CodeStatementRefused, "WRONG_TOOL", ""},
		{"sleep", map[string]any{"sql": "SELECT pg_sleep(10)"}, agent.CodeStatementRefused, "FUNCTION_NOT_ALLOWED", ""},
		{"user function", map[string]any{"sql": "SELECT bump()"}, agent.CodeStatementRefused, "FUNCTION_NOT_ALLOWED", ""},
		{"two statements", map[string]any{"sql": "SELECT 1; SELECT 2"}, agent.CodeStatementRefused, "MULTIPLE_STATEMENTS", ""},
		{"ddl", map[string]any{"sql": "DROP TABLE leads"}, agent.CodeStatementRefused, "DDL_NOT_ALLOWED", ""},
		{"locking read", map[string]any{"sql": "SELECT * FROM leads FOR UPDATE"}, agent.CodeStatementRefused, "LOCKING_READ", ""},
		{"parse error", map[string]any{"sql": "SELEC 1"}, agent.CodeStatementRefused, "PARSE_ERROR", ""},
		{"unknown argument", map[string]any{"sql": "SELECT 1", "limit": 5}, agent.CodeInvalidArgument, "", ""},
		{"missing sql", map[string]any{}, agent.CodeInvalidArgument, "", ""},
		{"bad run id", map[string]any{"sql": "SELECT 1", "runId": "run_7f3k"}, agent.CodeInvalidArgument, "", ""},
		{"too few params", map[string]any{"sql": "SELECT * FROM leads WHERE id = $1"}, agent.CodeInvalidArgument, "", ""},
		{"object param", map[string]any{"sql": "SELECT $1::text", "params": []any{map[string]any{"a": 1}}}, agent.CodeInvalidArgument, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, isError := h.query(t, c.args)
			requireToolError(t, body, isError, c.code, c.reason, c.sqlState)
		})
	}
}

func TestReadsRunReadOnly(t *testing.T) {
	t.Parallel()
	adminURL, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())

	// Past the engine's policy, the database still refuses a write inside a
	// read: the agent role may INSERT into audit, but not from a read.
	_, err := h.reader.Read(context.Background(), "SELECT bump()", nil, action.Statement{})
	te := agenttest.ToolError(err)
	require.Equal(t, agent.CodeSQLError, te.Code)
	require.Equal(t, "25006", te.SQLState, "read_only_sql_transaction")

	db, err := pgdial.Connect(context.Background(), adminURL)
	require.NoError(t, err)
	defer db.Close(context.Background())
	var exists bool
	require.NoError(t, db.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM audit)`).Scan(&exists))
	require.False(t, exists)
}

func TestQueryWhenTheDatabaseIsDown(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "postgres://nobody:x@127.0.0.1:1/none?sslmode=disable&connect_timeout=2", sqlguard.DefaultLimits())
	body, isError := h.query(t, map[string]any{"sql": "SELECT 1"})
	requireToolError(t, body, isError, agent.CodeUnavailable, "", "")
	require.NotContains(t, body["message"], "nobody", "no connection details in the error")
}

// A timestamptz is RFC 3339 UTC with Z whatever zone the session prints in,
// and keeps its fractional seconds (CONTRACT.md, Wire format).
func TestQueryReturnsTimestamptzAsUTC(t *testing.T) {
	t.Parallel()
	adminURL, agentURL := testDB(t)
	admin, err := pgdial.Connect(context.Background(), adminURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	_, err = admin.Exec(context.Background(), `ALTER ROLE `+pgx.Identifier{agentRole(t, agentURL)}.Sanitize()+` SET TimeZone TO 'Europe/Tallinn'`)
	require.NoError(t, err)
	_, err = admin.Exec(context.Background(), `UPDATE leads SET created = '2026-11-12 12:08:04.513958+00' WHERE id = 1`)
	require.NoError(t, err)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())

	body, isError := h.query(t, map[string]any{
		"sql": "SELECT created, created::text AS shown FROM leads WHERE id = 1",
	})
	require.False(t, isError, "%v", body)
	row := body["rows"].([]any)[0].(map[string]any)
	require.Equal(t, "2026-11-12 12:08:04.513958+00", row["shown"], "text columns are as Postgres printed them, in the engine's UTC whatever the role's TimeZone")
	require.Equal(t, "2026-11-12T12:08:04.513958Z", row["created"])
}

func agentRole(t *testing.T, agentURL string) string {
	t.Helper()
	u, err := url.Parse(agentURL)
	require.NoError(t, err)
	return u.User.Username()
}
