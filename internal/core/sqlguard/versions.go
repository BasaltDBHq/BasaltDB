package sqlguard

import (
	"errors"
	"fmt"
	"strings"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/basaltdbhq/basaltdb/internal/lib/sqlident"
)

// RowSource is a relation in a read's top-level FROM whose rows the engine
// can identify, if it turns out to be a guarded table (recorded reads,
// owner decision #7).
type RowSource struct {
	Schema string
	Name   string
	// Alias is the name the statement refers to the relation by, if any.
	Alias string
}

// RegName is the relation's name quoted for to_regclass. The parser has
// already folded unquoted identifiers, so every part is quoted as is.
func (s RowSource) RegName() string {
	if s.Schema == "" {
		return sqlident.Quote(s.Name)
	}
	return sqlident.Quote(s.Schema, s.Name)
}

// ref is how the statement names the relation's columns.
func (s RowSource) ref() []string {
	switch {
	case s.Alias != "":
		return []string{s.Alias}
	case s.Schema != "":
		return []string{s.Schema, s.Name}
	}
	return []string{s.Name}
}

// Versioned is a row source that is a guarded table, with its primary key.
type Versioned struct {
	Source RowSource
	PKCols []string
}

// VersionColumns is how many columns WithRowVersions appends per source:
// the primary key as a JSON object, and xmin.
const VersionColumns = 2

// ErrNoRowIdentity is a statement WithRowVersions cannot add columns to.
var ErrNoRowIdentity = errors.New("the statement has no row identity")

// WithRowVersions returns sql with, for each source in order, two output
// columns appended: jsonb_build_object of its primary key, and its xmin.
// The columns are added to the parse tree, which is deparsed; the agent's
// text is never concatenated. Parameters ($n) are kept.
func WithRowVersions(sql string, sources []Versioned) (string, error) {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return "", err
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return "", ErrNoRowIdentity
	}
	sel := stmts[0].GetStmt().GetSelectStmt()
	if sel == nil || rowSources(sel) == nil {
		return "", ErrNoRowIdentity
	}
	for i, v := range sources {
		if len(v.PKCols) == 0 {
			return "", fmt.Errorf("%w: %s has no primary key", ErrNoRowIdentity, v.Source.RegName())
		}
		ref := v.Source.ref()
		args := make([]*pganalyze.Node, 0, 2*len(v.PKCols))
		for _, col := range v.PKCols {
			args = append(args, pganalyze.MakeAConstStrNode(col, -1), columnRef(ref, col))
		}
		key := pganalyze.MakeFuncCallNode([]*pganalyze.Node{pganalyze.MakeStrNode("jsonb_build_object")}, args, -1)
		sel.TargetList = append(sel.TargetList,
			pganalyze.MakeResTargetNodeWithNameAndVal(fmt.Sprintf("__basalt_key_%d", i+1), key, -1),
			pganalyze.MakeResTargetNodeWithNameAndVal(fmt.Sprintf("__basalt_version_%d", i+1), columnRef(ref, "xmin"), -1))
	}
	return pgquery.Deparse(tree)
}

func columnRef(ref []string, col string) *pganalyze.Node {
	fields := make([]*pganalyze.Node, 0, len(ref)+1)
	for _, f := range ref {
		fields = append(fields, pganalyze.MakeStrNode(f))
	}
	return pganalyze.MakeColumnRefNode(append(fields, pganalyze.MakeStrNode(col)), -1)
}

// rowSources returns the relations of a top-level SELECT whose rows can
// carry extra output columns, or nil when the statement's shape cannot:
// set operations, VALUES, DISTINCT, GROUP BY, HAVING, or an aggregate
// outside a window collapse rows, so a row of output is not a row of a
// table. Relations inside subqueries, functions in FROM, CTE names, an
// aliased join and an alias that renames columns are left out.
func rowSources(sel *pganalyze.SelectStmt) []RowSource {
	if sel.GetOp() != pganalyze.SetOperation_SETOP_NONE || len(sel.GetValuesLists()) > 0 ||
		len(sel.GetDistinctClause()) > 0 || len(sel.GetGroupClause()) > 0 || sel.GetHavingClause() != nil ||
		hasAggregate(sel.GetTargetList()) || hasAggregate(sel.GetSortClause()) {
		return nil
	}
	ctes := map[string]bool{}
	for _, c := range sel.GetWithClause().GetCtes() {
		ctes[c.GetCommonTableExpr().GetCtename()] = true
	}
	var out []RowSource
	var walk func(n *pganalyze.Node)
	walk = func(n *pganalyze.Node) {
		switch {
		case n.GetRangeVar() != nil:
			rv := n.GetRangeVar()
			if (rv.GetSchemaname() == "" && ctes[rv.GetRelname()]) || len(rv.GetAlias().GetColnames()) > 0 {
				return
			}
			out = append(out, RowSource{Schema: rv.GetSchemaname(), Name: rv.GetRelname(), Alias: rv.GetAlias().GetAliasname()})
		case n.GetJoinExpr() != nil:
			j := n.GetJoinExpr()
			if j.GetAlias() != nil { // an aliased join hides its tables' names
				return
			}
			walk(j.GetLarg())
			walk(j.GetRarg())
		}
	}
	for _, n := range sel.GetFromClause() {
		walk(n)
	}
	return out
}

// hasAggregate reports whether nodes call an aggregate outside a window,
// not looking into subqueries (their aggregates are their own).
func hasAggregate(nodes []*pganalyze.Node) bool {
	found := false
	for _, n := range nodes {
		walkTree(n.ProtoReflect(), func(m protoreflect.Message) bool {
			switch v := m.Interface().(type) {
			case *pganalyze.SubLink:
				return false
			case *pganalyze.FuncCall:
				found = found || isAggregate(v)
			}
			return !found
		})
	}
	return found
}

func isAggregate(f *pganalyze.FuncCall) bool {
	if f.GetOver() != nil {
		return false
	}
	return aggregateFunctions[strings.TrimPrefix(nameOf(f.GetFuncname()), "pg_catalog.")] ||
		f.GetAggStar() || f.GetAggDistinct() || f.GetAggWithinGroup() || f.GetAggFilter() != nil || len(f.GetAggOrder()) > 0
}
