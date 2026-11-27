package sqlguard

import (
	"errors"
	"fmt"
	"strings"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fixableFunctions are the time functions without arguments a held write
// may use: the engine has Postgres evaluate them once, when it holds the
// write, and holds the statement with their values as typed literals. All
// return a timestamptz.
var fixableFunctions = toSet(`now transaction_timestamp statement_timestamp clock_timestamp`)

const typeTimestamptz = "timestamptz"

// fixableValueType is the type of the literal of a time SQL value function
// a held write may use, or "" for any other.
func fixableValueType(op pganalyze.SQLValueFunctionOp) string {
	switch op {
	case pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP, pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_TIMESTAMP_N:
		return typeTimestamptz
	case pganalyze.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP, pganalyze.SQLValueFunctionOp_SVFOP_LOCALTIMESTAMP_N:
		return "timestamp"
	case pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_DATE:
		return "date"
	case pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_TIME, pganalyze.SQLValueFunctionOp_SVFOP_CURRENT_TIME_N:
		return "timetz"
	default: // LOCALTIME has no zone and is refused as before; the rest are not times
		return ""
	}
}

// fixableType is the type of the literal that replaces n, or "" when n is
// not a time function the engine fixes.
func fixableType(n *pganalyze.Node) string {
	if f := n.GetFuncCall(); f != nil {
		name := strings.TrimPrefix(nameOf(f.GetFuncname()), "pg_catalog.")
		if fixableFunctions[name] && len(f.GetArgs()) == 0 && !f.GetAggStar() && f.GetOver() == nil {
			return typeTimestamptz
		}
		return ""
	}
	if v := n.GetSqlvalueFunction(); v != nil {
		return fixableValueType(v.GetOp())
	}
	return ""
}

// Column is a table column as an INSERT without a column list fills it,
// in the table's order (dropped columns left out).
type Column struct {
	Name string
	// Default is the column's default expression as Postgres prints it
	// (pg_get_expr), "" for none.
	Default string
	// Identity is an identity column, whose value comes from its sequence.
	Identity bool
	// Generated is a generated column, computed from the row.
	Generated bool
	// Volatile names a volatile function (pg_proc.provolatile 'v') the
	// default calls that the catalog records it depends on (functions of
	// extensions and of the app, not the built-ins, which nonRepeatable
	// knows by name); "" for none.
	Volatile string
}

// TimeFix is a held write's statement with the time functions it uses (and,
// for an INSERT without a column list, the ones in the defaults of the
// columns it leaves out) found, ready to take their values.
type TimeFix struct {
	tree *pganalyze.ParseResult
	// slots are the places that take one value each, in the order of Eval's
	// columns: every node of a slot is replaced by the same literal.
	slots []timeSlot
	// Eval is the SELECT that returns each slot's value as text, in order,
	// or "" when the statement needs nothing fixed.
	Eval string
}

type timeSlot struct {
	typ   string
	nodes []*pganalyze.Node
}

// PlanTimes finds the time functions of a held write (sql, which
// CheckRepeatable accepted) that the engine fixes. columns are the target
// table's columns when the write is an INSERT without a column list, and
// nil otherwise: a column it leaves to a default that uses a time function
// is added to the statement with that default, its time functions fixed
// too, because the approval binds every column of such an INSERT. A column
// left to an identity or to a default that gives another value on every run
// (nextval(), random(), ...) is refused with NOT_REPEATABLE, naming it:
// the write could never apply as approved.
func PlanTimes(sql string, columns []Column) (*TimeFix, error) {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return nil, &RefusalError{Reason: ReasonParseError, Detail: err.Error()}
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return nil, refuse(ReasonMultipleStatements, "%d statements; send exactly one", len(stmts))
	}
	fix := &TimeFix{tree: tree}
	for _, n := range timeNodes(stmts[0].GetStmt()) {
		fix.slots = append(fix.slots, timeSlot{typ: fixableType(n), nodes: []*pganalyze.Node{n}})
	}
	if ins := stmts[0].GetStmt().GetInsertStmt(); ins != nil && len(ins.GetCols()) == 0 && columns != nil {
		if err := fix.addDefaults(ins, columns); err != nil {
			return nil, err
		}
	}
	if len(fix.slots) == 0 {
		return fix, nil
	}
	targets := make([]*pganalyze.Node, 0, len(fix.slots))
	for _, s := range fix.slots {
		cast := &pganalyze.Node{Node: &pganalyze.Node_TypeCast{TypeCast: &pganalyze.TypeCast{
			Arg: cloneNode(s.nodes[0]), TypeName: typeName("text"), Location: -1,
		}}}
		targets = append(targets, pganalyze.MakeResTargetNodeWithVal(cast, -1))
	}
	eval := &pganalyze.ParseResult{Version: tree.GetVersion(), Stmts: []*pganalyze.RawStmt{{Stmt: &pganalyze.Node{
		Node: &pganalyze.Node_SelectStmt{SelectStmt: &pganalyze.SelectStmt{TargetList: targets}},
	}}}}
	if fix.Eval, err = pgquery.Deparse(eval); err != nil {
		return nil, err
	}
	return fix, nil
}

// Apply returns the statement with each slot replaced by its value, in
// Eval's order, as a literal of the slot's type. The tree is deparsed; no
// text is concatenated. A TimeFix is applied once.
func (f *TimeFix) Apply(values []string) (string, error) {
	if len(values) != len(f.slots) {
		return "", fmt.Errorf("%d values for %d fixed times", len(values), len(f.slots))
	}
	for i, s := range f.slots {
		for _, n := range s.nodes {
			n.Node = literal(values[i], s.typ).Node
		}
	}
	return pgquery.Deparse(f.tree)
}

// timeNodes are the nodes under root that fixableType fixes, in the order
// of the parse tree's fields (walkTree's order is not fixed), so a plan's
// Eval is the same for the same statement.
func timeNodes(root *pganalyze.Node) []*pganalyze.Node {
	var out []*pganalyze.Node
	var walk func(m protoreflect.Message)
	walk = func(m protoreflect.Message) {
		if n, ok := m.Interface().(*pganalyze.Node); ok && fixableType(n) != "" {
			out = append(out, n)
			return
		}
		fields := m.Descriptor().Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			switch {
			case fd.Message() == nil || fd.IsMap() || !m.Has(fd):
			case fd.IsList():
				l := m.Get(fd).List()
				for j := range l.Len() {
					walk(l.Get(j).Message())
				}
			default:
				walk(m.Get(fd).Message())
			}
		}
	}
	walk(root.ProtoReflect())
	return out
}

// addDefaults adds to ins (an INSERT without a column list) the columns it
// leaves to a default with a time function, with that default as their
// value, and refuses the columns left to a value that changes on every run.
// The INSERT gets a column list: the columns it filled by position, then
// the added ones.
func (f *TimeFix) addDefaults(ins *pganalyze.InsertStmt, columns []Column) error {
	given, ok := insertWidth(ins)
	if !ok || given >= len(columns) {
		return nil // the width is unknown (SELECT *, a set operation) or every column is given
	}
	var added []Column
	var exprs []*pganalyze.Node
	for _, c := range columns[given:] {
		switch {
		case c.Generated:
			continue
		case c.Identity:
			return refuse(ReasonNotRepeatable,
				"the INSERT leaves the identity column %q to its next value, which is another one when the approved write runs; "+
					"list the columns the INSERT sets, so the person approves exactly what is written", c.Name)
		case c.Default == "":
			continue
		case c.Volatile != "":
			return refuse(ReasonNotRepeatable,
				"the INSERT leaves the column %q to its default, which calls the volatile function %s and gives another value when the approved write runs; "+
					"list the columns the INSERT sets, so the person approves exactly what is written", c.Name, c.Volatile)
		}
		expr, err := defaultExpr(c.Default)
		if err != nil {
			return err
		}
		if what := nonRepeatable(expr.ProtoReflect()); what != "" {
			return refuse(ReasonNotRepeatable,
				"the INSERT leaves the column %q to its default %s, which gives another value when the approved write runs; "+
					"list the columns the INSERT sets, so the person approves exactly what is written", c.Name, what)
		}
		if len(timeNodes(expr)) == 0 {
			continue
		}
		// The default goes into the statement, so it must pass the policy
		// the held statement is checked with again when it applies.
		if _, err := Check("SELECT "+c.Default, ToolQuery); err != nil {
			var re *RefusalError
			if !errors.As(err, &re) {
				return err
			}
			return refuse(re.Reason,
				"the INSERT leaves the column %q to its default, which the engine would write into the held statement to fix its time, but the default is refused: %s; "+
					"list the columns the INSERT sets and give the column a value", c.Name, re.Detail)
		}
		added, exprs = append(added, c), append(exprs, expr)
	}
	if len(added) == 0 {
		return nil
	}
	rows := insertRows(ins)
	for _, expr := range exprs {
		template := timeNodes(expr)
		first := len(f.slots)
		for _, tn := range template {
			f.slots = append(f.slots, timeSlot{typ: fixableType(tn)})
		}
		for _, row := range rows {
			c := cloneNode(expr)
			for k, n := range timeNodes(c) {
				f.slots[first+k].nodes = append(f.slots[first+k].nodes, n)
			}
			if row.sel != nil {
				row.sel.TargetList = append(row.sel.TargetList, pganalyze.MakeResTargetNodeWithVal(c, -1))
			} else {
				row.list.Items = append(row.list.Items, c)
			}
		}
	}
	cols := make([]*pganalyze.Node, 0, given+len(added))
	for _, c := range columns[:given] {
		cols = append(cols, pganalyze.MakeResTargetNodeWithName(c.Name, -1))
	}
	for _, c := range added {
		cols = append(cols, pganalyze.MakeResTargetNodeWithName(c.Name, -1))
	}
	ins.Cols = cols
	return nil
}

// insertWidth is how many columns an INSERT without a column list fills by
// position, and false when the parse tree cannot tell.
func insertWidth(ins *pganalyze.InsertStmt) (int, bool) {
	sel := ins.GetSelectStmt().GetSelectStmt()
	switch {
	case ins.GetSelectStmt() == nil:
		return 0, true // DEFAULT VALUES
	case sel == nil || sel.GetOp() != pganalyze.SetOperation_SET_OPERATION_UNDEFINED && sel.GetOp() != pganalyze.SetOperation_SETOP_NONE:
		return 0, false
	case len(sel.GetValuesLists()) > 0:
		return len(sel.GetValuesLists()[0].GetList().GetItems()), true
	}
	for _, t := range sel.GetTargetList() {
		if hasStar(t) {
			return 0, false
		}
	}
	return len(sel.GetTargetList()), true
}

func hasStar(n *pganalyze.Node) bool {
	star := false
	walkTree(n.ProtoReflect(), func(m protoreflect.Message) bool {
		if _, ok := m.Interface().(*pganalyze.A_Star); ok {
			star = true
		}
		return !star
	})
	return star
}

// insertRow is one place an added column's value goes: a VALUES row, or
// the target list of a SELECT.
type insertRow struct {
	list *pganalyze.List
	sel  *pganalyze.SelectStmt
}

// insertRows are ins's rows, turning DEFAULT VALUES into one empty VALUES
// row.
func insertRows(ins *pganalyze.InsertStmt) []insertRow {
	if ins.GetSelectStmt() == nil {
		list := &pganalyze.List{}
		ins.SelectStmt = &pganalyze.Node{Node: &pganalyze.Node_SelectStmt{SelectStmt: &pganalyze.SelectStmt{
			ValuesLists: []*pganalyze.Node{{Node: &pganalyze.Node_List{List: list}}},
		}}}
		return []insertRow{{list: list}}
	}
	sel := ins.GetSelectStmt().GetSelectStmt()
	if len(sel.GetValuesLists()) == 0 {
		return []insertRow{{sel: sel}}
	}
	rows := make([]insertRow, 0, len(sel.GetValuesLists()))
	for _, v := range sel.GetValuesLists() {
		rows = append(rows, insertRow{list: v.GetList()})
	}
	return rows
}

// defaultExpr parses a column default as Postgres prints it.
func defaultExpr(def string) (*pganalyze.Node, error) {
	tree, err := pgquery.Parse("SELECT " + def)
	if err != nil {
		return nil, fmt.Errorf("a column default: %w", err)
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 || len(stmts[0].GetStmt().GetSelectStmt().GetTargetList()) != 1 {
		return nil, fmt.Errorf("a column default is not one expression: %q", def)
	}
	return stmts[0].GetStmt().GetSelectStmt().GetTargetList()[0].GetResTarget().GetVal(), nil
}

// cloneNode is a deep copy of n.
func cloneNode(n *pganalyze.Node) *pganalyze.Node {
	c, _ := proto.Clone(n).(*pganalyze.Node)
	return c
}

// literal is value as a literal of typ: '<value>'::typ.
func literal(value, typ string) *pganalyze.Node {
	return &pganalyze.Node{Node: &pganalyze.Node_TypeCast{TypeCast: &pganalyze.TypeCast{
		Arg: pganalyze.MakeAConstStrNode(value, -1), TypeName: typeName(typ), Location: -1,
	}}}
}

// typeName is the TypeName of the built-in type typ, qualified with
// pg_catalog so no type of the agent's search path stands in for it.
func typeName(typ string) *pganalyze.TypeName {
	return &pganalyze.TypeName{Names: []*pganalyze.Node{pganalyze.MakeStrNode("pg_catalog"), pganalyze.MakeStrNode(typ)}, Typemod: -1, Location: -1}
}

// FixedFrom reports whether held is exactly what PlanTimes and Apply make
// of sent with columns (the same columns PlanTimes was given when the
// write was held): the same statement, the same columns added in the same
// order with the same defaults, and in place of every time function the
// engine fixes, and only there, a string literal of that function's type.
// It compares parse trees, so spacing, comments and the case of unquoted
// names do not count; no literal of sent ever matches anything but itself.
func FixedFrom(held, sent string, columns []Column) bool {
	fix, err := PlanTimes(sent, columns)
	if err != nil {
		return false
	}
	// The plan's tree, its time functions still in place, deparsed and
	// parsed again so it reads as the held statement does.
	text, err := pgquery.Deparse(fix.tree)
	if err != nil {
		return false
	}
	tmpl, err := pgquery.Parse(text)
	if err != nil || len(tmpl.GetStmts()) != 1 {
		return false
	}
	tree, err := pgquery.Parse(held)
	if err != nil || len(tree.GetStmts()) != 1 {
		return false
	}
	return sameTree(tmpl.GetStmts()[0].GetStmt().ProtoReflect(), tree.GetStmts()[0].GetStmt().ProtoReflect())
}

// sameTree compares two parse trees field by field, ignoring where in the
// text each node was. A time function of a the engine fixes matches a
// string literal of its type in b (fixedLiteral), and nothing else.
func sameTree(a, b protoreflect.Message) bool {
	if a.Descriptor() != b.Descriptor() {
		return false
	}
	if n, ok := a.Interface().(*pganalyze.Node); ok {
		if typ := fixableType(n); typ != "" {
			h, ok := b.Interface().(*pganalyze.Node)
			return ok && fixedLiteral(h, typ)
		}
	}
	fields := a.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Name() == "location" || fd.Name() == "stmt_location" || fd.Name() == "stmt_len" {
			continue
		}
		if a.Has(fd) != b.Has(fd) {
			return false
		}
		if !a.Has(fd) {
			continue
		}
		if !sameValue(fd, a.Get(fd), b.Get(fd)) {
			return false
		}
	}
	return true
}

// fixedLiteral reports whether n is a non-null string literal cast to typ,
// as Apply writes it once deparsed and parsed again.
func fixedLiteral(n *pganalyze.Node, typ string) bool {
	cast := n.GetTypeCast()
	c := cast.GetArg().GetAConst()
	if cast == nil || c == nil || c.GetIsnull() || c.GetSval() == nil {
		return false
	}
	want := parsedLiteral(c.GetSval().GetSval(), typ)
	return want != nil && sameTree(want.ProtoReflect(), n.ProtoReflect())
}

// parsedLiteral is literal(value, typ) as the parser reads it back from
// the deparsed text, or nil when it does not read back as one cast.
func parsedLiteral(value, typ string) *pganalyze.Node {
	sel := &pganalyze.ParseResult{Stmts: []*pganalyze.RawStmt{{Stmt: &pganalyze.Node{
		Node: &pganalyze.Node_SelectStmt{SelectStmt: &pganalyze.SelectStmt{
			TargetList: []*pganalyze.Node{pganalyze.MakeResTargetNodeWithVal(literal(value, typ), -1)},
		}},
	}}}}
	text, err := pgquery.Deparse(sel)
	if err != nil {
		return nil
	}
	tree, err := pgquery.Parse(text)
	if err != nil || len(tree.GetStmts()) != 1 {
		return nil
	}
	targets := tree.GetStmts()[0].GetStmt().GetSelectStmt().GetTargetList()
	if len(targets) != 1 {
		return nil
	}
	return targets[0].GetResTarget().GetVal()
}

func sameValue(fd protoreflect.FieldDescriptor, a, b protoreflect.Value) bool {
	switch {
	case fd.IsList():
		la, lb := a.List(), b.List()
		if la.Len() != lb.Len() {
			return false
		}
		for i := range la.Len() {
			if fd.Message() != nil {
				if !sameTree(la.Get(i).Message(), lb.Get(i).Message()) {
					return false
				}
			} else if la.Get(i).Interface() != lb.Get(i).Interface() {
				return false
			}
		}
		return true
	case fd.IsMap():
		return false // the parse tree has no maps
	case fd.Message() != nil:
		return sameTree(a.Message(), b.Message())
	}
	return a.Interface() == b.Interface()
}
