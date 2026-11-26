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
// given per call, so a store adapter never holds a PII hook of its own,
// and nothing but the port calls the dictionary observer.

// piiObserverHome is the one non-test file outside internal/pii that calls
// the dictionary observer (pii.Observer.Observe): the agent's PII port.
const piiObserverHome = "internal/app/wire_agent_classes.go"

func TestStoreAdaptersHoldNoPIIHook(t *testing.T) {
	for _, f := range piiHookFindings(moduleTree(t), modulePath) {
		t.Errorf("%s: a write hands its returned rows to the agent's PII port through the Returned it is given per call; a store keeps no hook of its own", f)
	}
}

// Only the agent's PII port calls the dictionary observer: a second caller
// (a store's own hook, a wiring shortcut) would add values outside the one
// path the query and write rows share.
func TestOnlyTheAgentsPIIPortCallsTheObserver(t *testing.T) {
	for _, f := range piiObserverFindings(moduleTree(t), modulePath) {
		t.Errorf("%s; only the agent's PII port (%s) may", f, piiObserverHome)
	}
}

// piiHookFindings are the store adapters' imports of the PII package and
// their struct fields that hold a returned-rows hook: a func type that takes
// result columns and rows ([]action.Column, []map[string]any), or an
// interface with such a method, inline or named in any package of mod.
func piiHookFindings(pkgs map[string]*goPkg, mod string) []string {
	hooks := rowsHookTypes(pkgs, mod)
	var found []string
	for rel, pk := range pkgs {
		if !underAny(rel, storeAdapterRoots) {
			continue
		}
		for _, f := range pk.files {
			file := relFile(rel, f.name)
			imports := importNames(f.ast)
			for _, p := range imports {
				if p == mod+"/internal/pii" {
					found = append(found, file+": imports "+p)
				}
			}
			h := hookCheck{hooks: hooks, rel: rel, mod: mod, imports: imports}
			ast.Inspect(f.ast, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, fld := range st.Fields.List {
					if h.holds(fld.Type) {
						found = append(found, file+": struct field "+fieldName(fld)+" holds a returned-rows hook")
					}
				}
				return true
			})
		}
	}
	slices.Sort(found)
	return found
}

// rowsHookTypes are the named types of mod ("rel.Name") that take result
// rows: a func type, or an interface with a method, that does.
func rowsHookTypes(pkgs map[string]*goPkg, mod string) map[string]bool {
	out := map[string]bool{}
	for rel, pk := range pkgs {
		for _, f := range pk.files {
			actions := pkgNames(importNames(f.ast), mod+"/internal/core/action")
			for _, d := range f.ast.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.TYPE {
					continue
				}
				for _, s := range g.Specs {
					ts := s.(*ast.TypeSpec)
					if inlineRowsHook(ts.Type, actions) {
						out[rel+"."+ts.Name.Name] = true
					}
				}
			}
		}
	}
	return out
}

// hookCheck reads a field's type in one file of package rel.
type hookCheck struct {
	hooks   map[string]bool
	rel     string
	mod     string
	imports map[string]string
}

func (h hookCheck) holds(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.StarExpr:
		return h.holds(x.X)
	case *ast.ArrayType:
		return h.holds(x.Elt)
	case *ast.MapType:
		return h.holds(x.Value)
	case *ast.ChanType:
		return h.holds(x.Value)
	case *ast.Ident:
		return h.hooks[h.rel+"."+x.Name]
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		if !ok {
			return false
		}
		p, ok := h.imports[pkg.Name]
		if !ok || !strings.HasPrefix(p, h.mod+"/") {
			return false
		}
		return h.hooks[strings.TrimPrefix(p, h.mod+"/")+"."+x.Sel.Name]
	}
	return inlineRowsHook(e, pkgNames(h.imports, h.mod+"/internal/core/action"))
}

// inlineRowsHook reports whether e is a func type that takes result rows,
// or an interface with a method that does.
func inlineRowsHook(e ast.Expr, actions map[string]bool) bool {
	switch x := e.(type) {
	case *ast.FuncType:
		return takesResultRows(x, actions)
	case *ast.InterfaceType:
		for _, m := range x.Methods.List {
			if ft, ok := m.Type.(*ast.FuncType); ok && takesResultRows(ft, actions) {
				return true
			}
		}
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
			if kok && vok && k.Name == "string" && v.Name == "any" {
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

// pkgNames are the names a file uses for the package at path.
func pkgNames(imports map[string]string, path string) map[string]bool {
	out := map[string]bool{}
	for name, p := range imports {
		if p == path {
			out[name] = true
		}
	}
	return out
}

// piiObserverFindings are the uses of the dictionary observer's Observe
// (a call or a method value) in a non-test file outside internal/pii and
// piiObserverHome. A pii observer is a name declared as pii.Observer or
// *pii.Observer (a variable, parameter, result or struct field, in any
// package of mod), or assigned from pii.NewObserver; the method expression
// (*pii.Observer).Observe counts too, and so does any four-argument
// .Observe call (the observer's shape: context, classes, fields, rows).
func piiObserverFindings(pkgs map[string]*goPkg, mod string) []string {
	fields, locals := observerNames(pkgs, mod+"/internal/pii")
	var found []string
	eachFile(pkgs, func(rel, file string, f *ast.File, imports map[string]string) {
		if rel == "internal/pii" || file == piiObserverHome {
			return
		}
		pii := pkgNames(imports, mod+"/internal/pii")
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Observe" && len(call.Args) == 4 {
					found = append(found, file+": calls Observe with the observer's four arguments")
				}
				return true
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Observe" {
				return true
			}
			switch x := ast.Unparen(sel.X).(type) {
			case *ast.Ident:
				if locals[rel][x.Name] || fields[x.Name] {
					found = append(found, file+": uses the dictionary observer's Observe ("+x.Name+")")
				}
			case *ast.SelectorExpr:
				if fields[x.Sel.Name] {
					found = append(found, file+": uses the dictionary observer's Observe (."+x.Sel.Name+")")
				}
			case *ast.StarExpr:
				if isObserverType(x, pii) {
					found = append(found, file+": uses the method expression (*pii.Observer).Observe")
				}
			}
			return true
		})
	})
	slices.Sort(found)
	return slices.Compact(found)
}

// observerNames are the names that hold a pii observer: struct fields in
// any package, and per package its variables, parameters and results.
func observerNames(pkgs map[string]*goPkg, piiPath string) (fields map[string]bool, locals map[string]map[string]bool) {
	fields, locals = map[string]bool{}, map[string]map[string]bool{}
	for rel, pk := range pkgs {
		names := map[string]bool{}
		locals[rel] = names
		for _, f := range pk.files {
			pii := pkgNames(importNames(f.ast), piiPath)
			ast.Inspect(f.ast, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.StructType:
					for _, fld := range x.Fields.List {
						if isObserverType(fld.Type, pii) {
							for _, name := range fld.Names {
								fields[name.Name] = true
							}
						}
					}
				case *ast.Field:
					if isObserverType(x.Type, pii) {
						for _, name := range x.Names {
							names[name.Name] = true
						}
					}
				case *ast.ValueSpec:
					for i, name := range x.Names {
						if (x.Type != nil && isObserverType(x.Type, pii)) || (i < len(x.Values) && newsObserver(x.Values[i], pii)) {
							names[name.Name] = true
						}
					}
				case *ast.AssignStmt:
					if len(x.Lhs) == len(x.Rhs) {
						for i, v := range x.Rhs {
							if id, ok := x.Lhs[i].(*ast.Ident); ok && newsObserver(v, pii) {
								names[id.Name] = true
							}
						}
					}
				}
				return true
			})
		}
	}
	return fields, locals
}

// isObserverType reports whether e is pii.Observer or *pii.Observer.
func isObserverType(e ast.Expr, pii map[string]bool) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Observer" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && pii[x.Name]
}

// newsObserver reports whether e is a call of pii.NewObserver.
func newsObserver(e ast.Expr, pii map[string]bool) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "NewObserver" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && pii[x.Name]
}

// --- Probes --------------------------------------------------------------

func TestPIIHookRuleCatchesProbes(t *testing.T) {
	pkgs := probeTree(t, map[string]string{
		"internal/other/other.go": `package other

import (
	"context"

	"probe/internal/core/action"
)

type Rows func(ctx context.Context, cols []action.Column, rows []map[string]any) error

type Port interface {
	See(ctx context.Context, cols []action.Column, rows []map[string]any) error
}

type Plain func(ctx context.Context) error
`,
		"internal/platform/postgres/bad/bad.go": `package bad

import (
	"context"

	act "probe/internal/core/action"
	"probe/internal/other"
	"probe/internal/pii"
)

type local = func(context.Context, []act.Column, []map[string]any) error

type Store struct {
	selector  other.Rows
	iface     other.Port
	pointer   *other.Port
	list      []other.Rows
	named     local
	inline    func(context.Context, []act.Column, []map[string]any) error
	inlineIfc interface {
		Saw(context.Context, []act.Column, []map[string]any) error
	}
	fine  other.Plain
	fine2 func(context.Context) error
}

var _ = pii.X
`,
		"internal/platform/postgres/good/good.go": `package good

import "probe/internal/other"

type Store struct{ fine other.Plain }
`,
	})
	got := piiHookFindings(pkgs, "probe")
	want := []string{
		"internal/platform/postgres/bad/bad.go: imports probe/internal/pii",
		"internal/platform/postgres/bad/bad.go: struct field iface holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field inline holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field inlineIfc holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field list holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field named holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field pointer holds a returned-rows hook",
		"internal/platform/postgres/bad/bad.go: struct field selector holds a returned-rows hook",
	}
	if !slices.Equal(got, want) {
		t.Errorf("piiHookFindings:\n got %q\nwant %q", got, want)
	}
}

func TestPIIObserverRuleCatchesProbes(t *testing.T) {
	pkgs := probeTree(t, map[string]string{
		"internal/app/wire_agent_classes.go": `package app

import "probe/internal/pii"

type port struct{ o *pii.Observer }

func (p port) see() error { return p.o.Observe(nil, nil, nil, nil) }
`,
		"internal/pii/observe.go": `package pii

type Observer struct{}

func (o *Observer) Observe(a, b, c, d any) error { return o.Observe(a, b, c, d) }
`,
		"internal/hold/hold.go": `package hold

import "probe/internal/pii"

type Hook struct{ Obs *pii.Observer }
`,
		"internal/call/call.go": `package call

import p "probe/internal/pii"

func value(o *p.Observer) any { return o.Observe }

func made() error {
	obs := p.NewObserver(nil, nil)
	return obs.Observe(nil, nil, nil)
}

func expr() any { return (*p.Observer).Observe }
`,
		"internal/reach/reach.go": `package reach

import "probe/internal/hold"

func through(h hold.Hook) any { return h.Obs.Observe }

func four(x interface{ Observe(a, b, c, d any) error }) error { return x.Observe(1, 2, 3, 4) }
`,
		"internal/port/port.go": `package port

type Port interface{ Observe(a, b, c any) error }

type svc struct{ pii Port }

func (s svc) read() error { return s.pii.Observe(1, 2, 3) }
`,
	})
	got := piiObserverFindings(pkgs, "probe")
	want := []string{
		"internal/call/call.go: uses the dictionary observer's Observe (o)",
		"internal/call/call.go: uses the dictionary observer's Observe (obs)",
		"internal/call/call.go: uses the method expression (*pii.Observer).Observe",
		"internal/reach/reach.go: calls Observe with the observer's four arguments",
		"internal/reach/reach.go: uses the dictionary observer's Observe (.Obs)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("piiObserverFindings:\n got %q\nwant %q", got, want)
	}
}
