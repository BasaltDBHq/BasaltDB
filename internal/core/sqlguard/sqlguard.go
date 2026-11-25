// Package sqlguard is the engine's SQL policy: it parses one agent statement
// with the pure-Go wasm build of libpg_query, classifies it, collects the
// tables and functions it names, and refuses what the default policy does
// not allow (owner decisions #1 and #11).
//
// The first parse in a process compiles the wasm module (about 0.6 s), so
// only the long-running engine imports this package; the MCP shim and the
// CLI commands that do not parse must not.
package sqlguard

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Kind is the statement class the policy decides on.
type Kind string

// Statement kinds.
const (
	KindRead    Kind = "READ"
	KindWrite   Kind = "WRITE"
	KindDDL     Kind = "DDL"
	KindUtility Kind = "UTILITY"
)

// Op is the statement's operation: READ (a SELECT), INSERT, UPDATE, DELETE,
// MERGE, or the parse node name of anything else. READ is Basalt's op; the
// SQL word for it is SELECT (sqlWord).
type Op string

// sqlWord is the SQL command for op, as a refusal's detail names it.
func (op Op) sqlWord() string {
	if op == OpRead {
		return "SELECT"
	}
	return string(op)
}

// Operations the M1 tools accept, plus MERGE which is refused by name.
const (
	OpRead   Op = "READ"
	OpInsert Op = "INSERT"
	OpUpdate Op = "UPDATE"
	OpDelete Op = "DELETE"
	OpMerge  Op = "MERGE"
)

// Tool is the MCP tool a statement was sent to.
type Tool string

// Tools that run agent SQL.
const (
	ToolQuery Tool = "QUERY"
	ToolWrite Tool = "WRITE"
)

// Reason is why a statement was refused (CONTRACT.md, STATEMENT_REFUSED
// reasons).
type Reason string

// Refusal reasons.
const (
	ReasonParseError         Reason = "PARSE_ERROR"
	ReasonMultipleStatements Reason = "MULTIPLE_STATEMENTS"
	ReasonWrongTool          Reason = "WRONG_TOOL"
	ReasonDDL                Reason = "DDL_NOT_ALLOWED"
	ReasonUtility            Reason = "STATEMENT_NOT_ALLOWED"
	ReasonSelectInto         Reason = "SELECT_INTO"
	ReasonLockingRead        Reason = "LOCKING_READ"
	ReasonMerge              Reason = "MERGE_NOT_ALLOWED"
	ReasonDataModifyingWith  Reason = "DATA_MODIFYING_WITH"
	ReasonFunction           Reason = "FUNCTION_NOT_ALLOWED"
)

// Statement is what the engine needs from one agent statement.
type Statement struct {
	Kind Kind
	Op   Op
	// Tables are the relations the statement names, as written
	// (schema-qualified when the agent qualified them), sorted. CTE names are
	// left out.
	Tables []string
	// Target is the relation an INSERT, UPDATE or DELETE writes, as
	// written like Tables; "" for any other statement.
	Target string
	// Functions are the functions the statement calls, as written, sorted.
	Functions []string
	// ParamCount is the highest $n placeholder used, 0 when none.
	ParamCount int
	// RowSources are the relations of a SELECT whose rows the engine can
	// identify (recorded reads); nil when the statement's shape cannot
	// carry row identity, such as an aggregate.
	RowSources []RowSource
}

// RefusalError is a statement the policy does not allow.
type RefusalError struct {
	Reason Reason
	Detail string
}

func (r *RefusalError) Error() string {
	if r.Detail == "" {
		return string(r.Reason)
	}
	return string(r.Reason) + ": " + r.Detail
}

func refuse(reason Reason, format string, args ...any) *RefusalError {
	return &RefusalError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Check parses sql and applies the policy for tool. It returns the
// classified statement, or a *RefusalError with as much of the statement as
// was classified (the op of a refused statement is still recorded).
func Check(sql string, tool Tool) (Statement, error) {
	stmt, err := Classify(sql)
	if err != nil {
		return stmt, err
	}
	if r := checkTool(stmt, tool); r != nil {
		return stmt, r
	}
	return stmt, nil
}

func checkTool(stmt Statement, tool Tool) *RefusalError {
	switch tool {
	case ToolQuery:
		if stmt.Op != OpRead {
			return refuse(ReasonWrongTool, "query runs one SELECT; use write for %s", stmt.Op.sqlWord())
		}
	case ToolWrite:
		if stmt.Op != OpInsert && stmt.Op != OpUpdate && stmt.Op != OpDelete {
			return refuse(ReasonWrongTool, "write runs one INSERT, UPDATE or DELETE; use query for %s", stmt.Op.sqlWord())
		}
	default:
		return refuse(ReasonWrongTool, "unknown tool %q", tool)
	}
	return nil
}

// Classify parses one SQL string and applies the checks that do not depend
// on the tool: one statement, no DDL or utility statements, no SELECT INTO,
// no locking reads, no MERGE, no data-modifying WITH, functions on the
// allowlist only.
func Classify(sql string) (Statement, error) {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return Statement{}, &RefusalError{Reason: ReasonParseError, Detail: err.Error()}
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return Statement{}, refuse(ReasonMultipleStatements, "%d statements; send exactly one", len(stmts))
	}
	node := stmts[0].GetStmt()

	w := &walker{tables: map[string]bool{}, funcs: map[string]bool{}, ctes: map[string]bool{}}
	w.visit(node.ProtoReflect())
	stmt := Statement{Tables: w.sortedTables(), Functions: slices.AppendSeq([]string{}, maps.Keys(w.funcs)), ParamCount: w.maxParam}

	slices.Sort(stmt.Functions) // non-nil, so an empty list is [] and not null

	stmt.Target = targetOf(node)
	var reason Reason
	stmt.Kind, stmt.Op, reason = classifyNode(node)
	if reason != "" {
		return stmt, refuse(reason, "%s", stmt.Op.sqlWord())
	}
	if sel := node.GetSelectStmt(); sel != nil {
		stmt.RowSources = rowSources(sel)
	}
	if w.dataModifyingCTE != "" {
		return stmt, refuse(ReasonDataModifyingWith, "WITH %s changes data", w.dataModifyingCTE)
	}
	for _, f := range stmt.Functions {
		if !functionAllowed(f) {
			return stmt, refuse(ReasonFunction, "%s is not on the function allowlist", f)
		}
	}
	return stmt, nil
}

// targetOf is the relation an INSERT, UPDATE or DELETE writes, as written;
// "" for any other statement.
func targetOf(stmt *pganalyze.Node) string {
	var rel *pganalyze.RangeVar
	switch n := stmt.GetNode().(type) {
	case *pganalyze.Node_InsertStmt:
		rel = n.InsertStmt.GetRelation()
	case *pganalyze.Node_UpdateStmt:
		rel = n.UpdateStmt.GetRelation()
	case *pganalyze.Node_DeleteStmt:
		rel = n.DeleteStmt.GetRelation()
	}
	if rel == nil {
		return ""
	}
	return qualifiedName(rel.GetSchemaname(), rel.GetRelname())
}

func classifyNode(stmt *pganalyze.Node) (Kind, Op, Reason) {
	switch n := stmt.GetNode().(type) {
	case *pganalyze.Node_SelectStmt:
		if n.SelectStmt.GetIntoClause() != nil {
			return KindDDL, OpRead, ReasonSelectInto
		}
		if len(n.SelectStmt.GetLockingClause()) > 0 {
			return KindRead, OpRead, ReasonLockingRead
		}
		return KindRead, OpRead, ""
	case *pganalyze.Node_InsertStmt:
		return KindWrite, OpInsert, ""
	case *pganalyze.Node_UpdateStmt:
		return KindWrite, OpUpdate, ""
	case *pganalyze.Node_DeleteStmt:
		return KindWrite, OpDelete, ""
	case *pganalyze.Node_MergeStmt:
		return KindWrite, OpMerge, ReasonMerge
	}
	name := nodeName(stmt)
	if isDDL(name) {
		return KindDDL, Op(name), ReasonDDL
	}
	return KindUtility, Op(name), ReasonUtility
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

func nameOf(parts []*pganalyze.Node) string {
	s := make([]string, 0, len(parts))
	for _, p := range parts {
		s = append(s, p.GetString_().GetSval())
	}
	return strings.Join(s, ".")
}
