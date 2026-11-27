// Package pgstatement is the engine's Postgres statement check: it parses one agent statement
// with the pure-Go wasm build of libpg_query, classifies it, collects the
// tables and functions it names, and refuses what the default policy does
// not allow (owner decisions #1 and #11).
//
// The first parse in a process compiles the wasm module (about 0.6 s), so
// only the long-running engine imports this package; the MCP shim and the
// CLI commands that do not parse must not.
package pgstatement

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// sqlWord is the SQL command for op, as a refusal's detail names it: READ
// is Basalt's op, the SQL word for it is SELECT.
func sqlWord(op action.Op) string {
	if op == action.OpRead {
		return "SELECT"
	}
	return string(op)
}

func refuse(reason action.RefusalReason, format string, args ...any) *action.RefusalError {
	return &action.RefusalError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Check parses sql and applies the policy for tool. It returns the
// classified statement, or a *action.RefusalError with as much of the statement as
// was classified (the op of a refused statement is still recorded).
func Check(sql string, tool action.Tool) (action.Statement, error) {
	stmt, err := Classify(sql)
	if err != nil {
		return stmt, err
	}
	if r := checkTool(stmt, tool); r != nil {
		return stmt, r
	}
	return stmt, nil
}

func checkTool(stmt action.Statement, tool action.Tool) *action.RefusalError {
	switch tool {
	case action.ToolQuery:
		if stmt.Op != action.OpRead {
			return refuse(action.ReasonWrongTool, "query runs one SELECT; use write for %s", sqlWord(stmt.Op))
		}
	case action.ToolWrite:
		if stmt.Op != action.OpInsert && stmt.Op != action.OpUpdate && stmt.Op != action.OpDelete {
			return refuse(action.ReasonWrongTool, "write runs one INSERT, UPDATE or DELETE; use query for %s", sqlWord(stmt.Op))
		}
	default:
		return refuse(action.ReasonWrongTool, "unknown tool %q", tool)
	}
	return nil
}

// Classify parses one SQL string and applies the checks that do not depend
// on the tool: one statement, no DDL or utility statements, no SELECT INTO,
// no locking reads, no MERGE, no data-modifying WITH, functions on the
// allowlist only. The statement's Handle is its []RowSource (rowSources),
// nil for anything but a SELECT whose rows carry identity. A DDL or utility
// statement's op is OTHER; the refusal's detail names its parse node.
func Classify(sql string) (action.Statement, error) {
	_, node, err := parseOne(sql)
	if err != nil {
		return action.Statement{}, err
	}
	w := &walker{tables: map[string]bool{}, funcs: map[string]bool{}, ctes: map[string]bool{}}
	w.visit(node.ProtoReflect())
	stmt := action.Statement{Tables: w.sortedTables(), Target: targetOf(node), ParamCount: w.maxParam}
	var sources []RowSource // typed even when nil: the store reads it back as []RowSource
	stmt.Handle = sources

	op, word, reason := classifyNode(node)
	stmt.Op = op
	if reason != "" {
		return stmt, refuse(reason, "%s", word)
	}
	if sel := node.GetSelectStmt(); sel != nil {
		stmt.Handle = rowSources(sel)
	}
	if w.dataModifyingCTE != "" {
		return stmt, refuse(action.ReasonDataModifyingWith, "WITH %s changes data", w.dataModifyingCTE)
	}
	// Sorted, so the refusal names the same function every time; the name
	// is the one written, schema and all.
	for _, f := range slices.Sorted(maps.Keys(w.funcs)) {
		if !functionAllowed(f) {
			return stmt, refuse(action.ReasonFunction, "%s is not on the function allowlist", f)
		}
	}
	return stmt, nil
}

// parseOne parses sql, which must be exactly one statement, and returns the
// parse tree and that statement, or a *action.RefusalError: PARSE_ERROR,
// or MULTIPLE_STATEMENTS for none or more than one.
func parseOne(sql string) (*pganalyze.ParseResult, *pganalyze.Node, error) {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return nil, nil, &action.RefusalError{Reason: action.ReasonParseError, Detail: err.Error()}
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return nil, nil, refuse(action.ReasonMultipleStatements, "%d statements; send exactly one", len(stmts))
	}
	return tree, stmts[0].GetStmt(), nil
}

// targetOf is the relation a write writes, as written: a data-modifying
// WITH's first, then the statement's own (writtenRelation); "" for any
// other statement.
func targetOf(stmt *pganalyze.Node) string {
	var with *pganalyze.WithClause
	switch n := stmt.GetNode().(type) {
	case *pganalyze.Node_SelectStmt:
		with = n.SelectStmt.GetWithClause()
	case *pganalyze.Node_InsertStmt:
		with = n.InsertStmt.GetWithClause()
	case *pganalyze.Node_UpdateStmt:
		with = n.UpdateStmt.GetWithClause()
	case *pganalyze.Node_DeleteStmt:
		with = n.DeleteStmt.GetWithClause()
	case *pganalyze.Node_MergeStmt:
		with = n.MergeStmt.GetWithClause()
	}
	for _, c := range with.GetCtes() {
		if t := targetOf(c.GetCommonTableExpr().GetCtequery()); t != "" {
			return t
		}
	}
	return writtenRelation(stmt)
}

// writtenRelation is the relation an INSERT, UPDATE, DELETE or MERGE
// itself writes, as written, or "" for any other statement.
func writtenRelation(stmt *pganalyze.Node) string {
	var rel *pganalyze.RangeVar
	switch n := stmt.GetNode().(type) {
	case *pganalyze.Node_InsertStmt:
		rel = n.InsertStmt.GetRelation()
	case *pganalyze.Node_UpdateStmt:
		rel = n.UpdateStmt.GetRelation()
	case *pganalyze.Node_DeleteStmt:
		rel = n.DeleteStmt.GetRelation()
	case *pganalyze.Node_MergeStmt:
		rel = n.MergeStmt.GetRelation()
	}
	if rel == nil {
		return ""
	}
	return qualifiedName(rel.GetSchemaname(), rel.GetRelname())
}

// classifyNode returns the statement's op, the word a refusal's detail
// names it by, and the reason it is refused, "" when it is not. A statement
// outside READ, INSERT, UPDATE, DELETE and MERGE is OTHER, named by its
// parse node (DropStmt, VariableSetStmt, ...): no parse node name reaches
// an op.
func classifyNode(stmt *pganalyze.Node) (action.Op, string, action.RefusalReason) {
	switch n := stmt.GetNode().(type) {
	case *pganalyze.Node_SelectStmt:
		if n.SelectStmt.GetIntoClause() != nil {
			return action.OpRead, sqlWord(action.OpRead), action.ReasonSelectInto
		}
		if len(n.SelectStmt.GetLockingClause()) > 0 {
			return action.OpRead, sqlWord(action.OpRead), action.ReasonLockingRead
		}
		return action.OpRead, sqlWord(action.OpRead), ""
	case *pganalyze.Node_InsertStmt:
		return action.OpInsert, sqlWord(action.OpInsert), ""
	case *pganalyze.Node_UpdateStmt:
		return action.OpUpdate, sqlWord(action.OpUpdate), ""
	case *pganalyze.Node_DeleteStmt:
		return action.OpDelete, sqlWord(action.OpDelete), ""
	case *pganalyze.Node_MergeStmt:
		return action.OpMerge, sqlWord(action.OpMerge), action.ReasonMerge
	}
	name := nodeName(stmt)
	if isDDL(name) {
		return action.OpOther, name, action.ReasonDDL
	}
	return action.OpOther, name, action.ReasonUtility
}

func nodeName(stmt *pganalyze.Node) string {
	m := stmt.ProtoReflect()
	field := m.WhichOneof(m.Descriptor().Oneofs().ByName("node"))
	if field == nil {
		return "Unknown"
	}
	return string(field.Message().Name())
}

var ddlPrefixes = []string{
	"Create", "Alter", "Drop", "Truncate", "Index", "View", "Rename", "Grant",
	"Comment", "Reindex", "Cluster", "Refresh", "SecLabel", "Rule", "Import",
}

func isDDL(nodeName string) bool {
	for _, p := range ddlPrefixes {
		if strings.HasPrefix(nodeName, p) {
			return true
		}
	}
	return false
}

type walker struct {
	tables           map[string]bool
	funcs            map[string]bool
	ctes             map[string]bool
	dataModifyingCTE string
	maxParam         int
}

// visit walks every message in the parse tree generically, so a node type
// added in a later grammar cannot hide a table or a function call.
func (w *walker) visit(root protoreflect.Message) {
	walkTree(root, func(m protoreflect.Message) bool {
		switch v := m.Interface().(type) {
		case *pganalyze.RangeVar:
			w.tables[qualifiedName(v.GetSchemaname(), v.GetRelname())] = true
		case *pganalyze.FuncCall:
			w.funcs[nameOf(v.GetFuncname())] = true
		case *pganalyze.ParamRef:
			w.maxParam = max(w.maxParam, int(v.GetNumber()))
		case *pganalyze.CommonTableExpr:
			w.ctes[v.GetCtename()] = true
			switch v.GetCtequery().GetNode().(type) {
			case *pganalyze.Node_InsertStmt, *pganalyze.Node_UpdateStmt, *pganalyze.Node_DeleteStmt, *pganalyze.Node_MergeStmt:
				w.dataModifyingCTE = v.GetCtename()
			}
		}
		return true
	})
}

// walkTree calls f on m and every message below it, depth first; f
// returns false to skip a message's children.
func walkTree(m protoreflect.Message, f func(protoreflect.Message) bool) {
	if !f(m) {
		return
	}
	m.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := val.List()
			for i := range l.Len() {
				walkTree(l.Get(i).Message(), f)
			}
		case fd.Message() != nil && !fd.IsMap():
			walkTree(val.Message(), f)
		}
		return true
	})
}

func qualifiedName(schema, name string) string {
	if schema == "" {
		return name
	}
	return schema + "." + name
}

func (w *walker) sortedTables() []string {
	out := make([]string, 0, len(w.tables))
	for t := range w.tables {
		if w.ctes[t] { // a CTE name used in FROM is not a table
			continue
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// funcName is the name a call names, without a pg_catalog qualifier: the
// name the engine's function lists know it by.
func funcName(f *pganalyze.FuncCall) string {
	return unqualified(nameOf(f.GetFuncname()))
}

// unqualified is a function name as written without its pg_catalog
// qualifier, if it has one.
func unqualified(name string) string {
	return strings.TrimPrefix(name, "pg_catalog.")
}

func nameOf(parts []*pganalyze.Node) string {
	s := make([]string, 0, len(parts))
	for _, p := range parts {
		s = append(s, p.GetString_().GetSval())
	}
	return strings.Join(s, ".")
}
