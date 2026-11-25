package sqllang_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// checker is a store's statement check over a fixed answer.
type checker struct {
	stmt  action.Statement
	err   error
	sql   string
	tool  action.Tool
	calls int
}

func (c *checker) Check(sql string, tool action.Tool) (action.Statement, error) {
	c.calls++
	c.sql, c.tool = sql, tool
	return c.stmt, c.err
}

func TestCheckPassesTheTextToTheStoreCheck(t *testing.T) {
	t.Parallel()
	c := &checker{stmt: action.Statement{Op: action.OpSelect, ParamCount: 1, Tables: []string{"public.t"}}}
	stmt, err := sqllang.New(c).Check(agentstore.Request{Text: "SELECT $1", Params: []any{1}}, action.ToolQuery)
	require.NoError(t, err)
	require.Equal(t, c.stmt, stmt)
	require.Equal(t, "SELECT $1", c.sql)
	require.Equal(t, action.ToolQuery, c.tool)
}

func TestCheckReturnsTheStoreRefusalWithoutCountingArgs(t *testing.T) {
	t.Parallel()
	refusal := errors.New("refused")
	c := &checker{stmt: action.Statement{Op: action.OpOther, ParamCount: 3}, err: refusal}
	stmt, err := sqllang.New(c).Check(agentstore.Request{Text: "DROP TABLE t"}, action.ToolWrite)
	require.ErrorIs(t, err, refusal)
	require.Equal(t, action.OpOther, stmt.Op)
}

// TestCheckCountsPlaceholders: a mismatch is INVALID_ARGUMENT with the
// statement still returned, so the refusal records its op.
func TestCheckCountsPlaceholders(t *testing.T) {
	t.Parallel()
	c := &checker{stmt: action.Statement{Op: action.OpUpdate, ParamCount: 2}}
	stmt, err := sqllang.New(c).Check(agentstore.Request{Text: "UPDATE t SET a = $1 WHERE id = $2", Params: []any{1}}, action.ToolWrite)
	var ae *guidance.ArgumentError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, "the statement uses 2 parameters ($1..$2) but 1 were given", ae.Message)
	require.Equal(t, action.OpUpdate, stmt.Op)
}

func TestCheckLimitsParamsTo64KiB(t *testing.T) {
	t.Parallel()
	c := &checker{stmt: action.Statement{Op: action.OpSelect, ParamCount: 1}}
	// A string of n bytes encodes to n+4 bytes of JSON: ["..."].
	fits := strings.Repeat("a", 64<<10-4)
	_, err := sqllang.New(c).Check(agentstore.Request{Text: "SELECT $1", Params: []any{fits}}, action.ToolQuery)
	require.NoError(t, err)

	_, err = sqllang.New(c).Check(agentstore.Request{Text: "SELECT $1", Params: []any{fits + "a"}}, action.ToolQuery)
	var ae *guidance.ArgumentError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, "params must encode to at most 64 KiB of JSON", ae.Message)
}

// TestRefusalTexts pins every revision a statement refusal asks for.
func TestRefusalTexts(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]string{
		string(action.ReasonParseError):         "Fix the SQL syntax as the message says, then call again.",
		string(action.ReasonMultipleStatements): "Send exactly one statement per call: split it into separate calls.",
		string(action.ReasonWrongTool):          "Send SELECT with query, and INSERT, UPDATE and DELETE with write.",
		string(action.ReasonUtility):            "Only SELECT (query) and INSERT, UPDATE, DELETE (write) are allowed: use one of them.",
		string(action.ReasonSelectInto):         "SELECT INTO creates a table: rewrite it as a plain SELECT.",
		string(action.ReasonLockingRead):        "Drop FOR UPDATE and the other lock clauses: query reads without locking.",
		string(action.ReasonMerge):              "MERGE is not allowed: use separate INSERT, UPDATE and DELETE statements.",
		string(action.ReasonDataModifyingWith):  "Move the INSERT, UPDATE or DELETE out of the WITH and send it as its own write.",
		string(action.ReasonFunction):           "Remove the call to the refused function the message names and use plain SQL.",
		string(action.ReasonNotRepeatable):      "Rewrite the write with fixed values instead of ones that change between runs, then call it again.",
	} {
		got, ok := sqllang.Language{}.RefusalText(reason)
		require.True(t, ok, reason)
		require.Equal(t, want, got, reason)
	}
	got, ok := sqllang.Language{}.RefusalText(string(action.ReasonDDL))
	require.False(t, ok)
	require.Empty(t, got)
}

// TestReadRow is the query that reads one row by its key: the key's columns
// in order, quoted, each a parameter.
func TestReadRow(t *testing.T) {
	t.Parallel()
	req := sqllang.Language{}.ReadRow("public.leads", map[string]any{"id": json.Number("42"), "Tenant": "a"})
	require.Equal(t, agentstore.Request{
		Text:   `SELECT * FROM public.leads WHERE "Tenant" = $1 AND "id" = $2`,
		Params: []any{"a", json.Number("42")},
	}, req)

	req = sqllang.Language{}.ReadRow(`"S"."t"`, map[string]any{"a\x00\"b": 1})
	require.Equal(t, `SELECT * FROM "S"."t" WHERE "a""b" = $1`, req.Text, "a quote doubled, a NUL dropped")
}

// Args names a request's arguments as query and write take them: sql, and
// params only when there are some.
func TestArgs(t *testing.T) {
	t.Parallel()
	var l sqllang.Language
	require.Equal(t, map[string]any{"sql": "SELECT 1"}, l.Args(agentstore.Request{Text: "SELECT 1"}))
	require.Equal(t, map[string]any{"sql": "SELECT 1"}, l.Args(agentstore.Request{Text: "SELECT 1", Params: []any{}}))
	require.Equal(t, map[string]any{"sql": "SELECT $1", "params": []any{"a"}}, l.Args(agentstore.Request{Text: "SELECT $1", Params: []any{"a"}}))
}
