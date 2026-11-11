package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
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
	reader *agentdb.Reader
}

func newHarness(t *testing.T, agentURL string, limits sqlguard.Limits) harness {
	t.Helper()
	return newHarnessConns(t, agentURL, limits, 2)
}

// newHarnessConns is newHarness with a pool of conns connections.
func newHarnessConns(t *testing.T, agentURL string, limits sqlguard.Limits, conns int32) harness {
	t.Helper()
	pool, err := agentdb.NewPool(context.Background(), agentURL, conns)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	reader := agentdb.NewReader(pool, limits, time.Now)
	store := agentdb.NewStore(pool, limits, time.Now)
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: reader, Store: store, Reads: store, Approvals: store, Reverts: store,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
	})
	return harness{
		server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...),
		reader: reader,
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
	require.Equal(t, "2026-11-10 06:02:11+00", first["created"])
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
	_, err := h.reader.Read(context.Background(), "SELECT bump()", nil, nil)
	te := agent.ToolError(err)
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
