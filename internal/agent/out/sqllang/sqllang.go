// Package sqllang is the agent's SQL language: what the agent service asks
// of a store that speaks SQL (Postgres) about its requests, in place of
// reading the SQL itself. It checks a request's parameters against its
// placeholders, gives the revision each statement refusal and each limit
// asks for, reads the table and key Postgres and the guard name in their
// error messages, writes the request that reads one row, and parses and
// prints schema.table names.
package sqllang

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/sqlident"
)

// maxParamsBytes is the limit of the guard's validating ledger functions
// (CONTRACT.md, basalt_meta): parameters up to 64 KiB.
const maxParamsBytes = 64 << 10

// Checker checks a statement against the engine's SQL policy for a tool,
// and returns it as the store will run it, or an *action.RefusalError.
type Checker interface {
	Check(sql string, tool action.Tool) (action.Statement, error)
}

// Language is the SQL language over a store's statement check.
type Language struct {
	checker Checker
}

// New returns the SQL language whose Check runs checker's.
func New(checker Checker) Language {
	return Language{checker: checker}
}

// Check checks req's text with the store's check for tool, then its
// parameters (checkArgs). The statement is returned with a parameter error,
// so the refusal is recorded with its op.
func (l Language) Check(req agentstore.Request, tool action.Tool) (action.Statement, error) {
	stmt, err := l.checker.Check(req.Text, tool)
	if err == nil {
		err = checkArgs(stmt, req.Params)
	}
	return stmt, err
}

// checkArgs checks the parameters match the statement's placeholders and
// fit the guard's ledger limit.
func checkArgs(stmt action.Statement, params []any) error {
	if stmt.ParamCount != len(params) {
		return &guidance.ArgumentError{Message: fmt.Sprintf("the statement uses %d parameters ($1..$%d) but %d were given",
			stmt.ParamCount, stmt.ParamCount, len(params))}
	}
	raw, err := json.Marshal(params)
	if err != nil || len(raw) > maxParamsBytes {
		return &guidance.ArgumentError{Message: "params must encode to at most 64 KiB of JSON"}
	}
	return nil
}

// refusedText is the revision each statement refusal asks for.
var refusedText = map[string]string{
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
}

// RefusalText is the revision a statement refusal of reason asks for, and
// false for a reason the agent does not fix by rewriting.
func (Language) RefusalText(reason string) (string, bool) {
	text, ok := refusedText[reason]
	return text, ok
}

// ReadRow is the request that reads the row of target with key: the key's
// columns in order, each a parameter.
func (Language) ReadRow(target string, key map[string]any) agentstore.Request {
	cols := make([]string, 0, len(key))
	for c := range key {
		cols = append(cols, c)
	}
	slices.Sort(cols)
	conds, params := make([]string, 0, len(cols)), make([]any, 0, len(cols))
	for i, c := range cols {
		conds = append(conds, fmt.Sprintf("%s = $%d", sqlident.Quote(c), i+1))
		params = append(params, key[c])
	}
	return agentstore.Request{Text: "SELECT * FROM " + target + " WHERE " + strings.Join(conds, " AND "), Params: params}
}

// Args is req as the query and write tools take it: its text as sql, and
// its parameters as params only when there are some.
func (Language) Args(req agentstore.Request) map[string]any {
	args := map[string]any{"sql": req.Text}
	if len(req.Params) > 0 {
		args["params"] = req.Params
	}
	return args
}
