package archtest

import (
	"go/ast"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// The rows the agent gets, a read's and a write's returned rows, reach the
// PII dictionary through one port: the agent service's PIIObserver. A
// write hands its returned rows to that port through the Returned it is
// given per call, so a store adapter never holds a PII hook of its own.

const (
	piiPkg    = "github.com/basaltdbhq/basaltdb/internal/pii"
	actionPkg = "github.com/basaltdbhq/basaltdb/internal/core/action"
)

// piiObserverHome is the one non-test file outside internal/pii that calls
// the dictionary observer (pii.Observer.Observe): the agent's PII port.
const piiObserverHome = "internal/app/wire_agent_classes.go"

// A store adapter imports nothing of the PII package and keeps no
// returned-rows hook: no struct field of a func type that takes result
// columns and rows ([]action.Column, []map[string]any), inline or named.
func TestStoreAdaptersHoldNoPIIHook(t *testing.T) {
	pkgs := moduleTree(t)
	var found []string
	for rel, pk := range pkgs {
		if !underAny(rel, storeAdapterRoots) {
			continue
		}
		hooks := map[string]bool{}
		for _, f := range pk.files {
			actions := actionNames(importNames(f.ast))
			for _, d := range f.ast.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.TYPE {
					continue
				}
				for _, s := range g.Specs {
					ts := s.(*ast.TypeSpec)
					if ft, ok := ts.Type.(*ast.FuncType); ok && takesResultRows(ft, actions) {
						hooks[ts.Name.Name] = true
					}
				}
			}
		}
		for _, f := range pk.files {
			file := relFile(rel, f.name)
			imports := importNames(f.ast)
			for _, p := range imports {
				if p == piiPkg {
					found = append(found, file+": imports "+piiPkg)
				}
			}
			actions := actionNames(imports)
			ast.Inspect(f.ast, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, fld := range st.Fields.List {
					if isRowsHook(fld.Type, hooks, actions) {
						found = append(found, file+": struct field "+fieldName(fld)+" holds a returned-rows hook")
					}
				}
				return true
			})
		}
	}
	slices.Sort(found)
	for _, f := range found {
		t.Errorf("%s: a write hands its returned rows to the agent's PII port through the Returned it is given per call; a store keeps no hook of its own", f)
	}
}

// Only the agent's PII port calls the dictionary observer: a second caller
// (a store's own hook, a wiring shortcut) would add values outside the one
// path the query and write rows share.
func TestOnlyTheAgentsPIIPortCallsTheObserver(t *testing.T) {
	pkgs := moduleTree(t)
	var found []string
	eachFile(pkgs, func(rel, file string, f *ast.File, imports map[string]string) {
		if rel == "internal/pii" || file == piiObserverHome || !slices.Contains(mapValues(imports), piiPkg) {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// pii.Observer.Observe takes the context, the classes, the
			// fields and the rows; the port's Observe takes three.
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Observe" && len(call.Args) == 4 {
				found = append(found, file+": calls the dictionary observer")
			}
			return true
		})
	})
	slices.Sort(found)
	for _, f := range found {
		t.Errorf("%s; only the agent's PII port (%s) may", f, piiObserverHome)
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// actionNames are the names a file uses for the core action package.
func actionNames(imports map[string]string) map[string]bool {
	out := map[string]bool{}
	for name, p := range imports {
		if p == actionPkg {
			out[name] = true
		}
	}
	return out
}

func isRowsHook(e ast.Expr, hooks, actions map[string]bool) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return hooks[x.Name]
	case *ast.FuncType:
		return takesResultRows(x, actions)
	}
	return false
}

// takesResultRows reports whether ft takes result columns
// ([]action.Column) and rows ([]map[string]any).
func takesResultRows(ft *ast.FuncType, actions map[string]bool) bool {
	var cols, rows bool
	for _, p := range ft.Params.List {
		a, ok := p.Type.(*ast.ArrayType)
		if !ok || a.Len != nil {
			continue
		}
		switch elt := a.Elt.(type) {
		case *ast.SelectorExpr:
			if x, ok := elt.X.(*ast.Ident); ok && actions[x.Name] && elt.Sel.Name == "Column" {
				cols = true
			}
		case *ast.MapType:
			k, kok := elt.Key.(*ast.Ident)
			v, vok := elt.Value.(*ast.Ident)
			if kok && vok && k.Name == "string" && (v.Name == "any" || v.Name == "interface{}") {
				rows = true
			}
		}
	}
	return cols && rows
}

func fieldName(f *ast.Field) string {
	if len(f.Names) == 0 {
		return "(embedded)"
	}
	names := make([]string, len(f.Names))
	for i, n := range f.Names {
		names[i] = n.Name
	}
	return strings.Join(names, ", ")
}
