package archtest

import (
	"bufio"
	"fmt"
	"go/ast"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The shape rules hold every domain to one way of building a service and
// one way of serving MCP tools:
//
//   - a domain's Service gets every port in its constructor: it has no
//     exported Set* method, and no exported With*, Use* or Wire* method that
//     assigns a field of its receiver;
//   - an exported function or method of an in/*mcp package that returns a
//     slice of tools (alone or with an error, of pointers, or a named slice)
//     is func Tools(port, mount) []mcpserver.Tool;
//   - no in/ package refuses the admin credential itself: internal/app wraps
//     every served tool once;
//   - ids come from internal/lib/uniqueid (the forbidigo lint in
//     .golangci.yml); a //nolint:forbidigo is a baseline entry;
//   - the service-to-service edges are the ones ARCHITECTURE.md lists.
//
// The breaks that exist today are in shape_baseline.txt, which only shrinks.
// Each line names the function that holds the finding, with a count when the
// function holds more than one, so a second break never hides behind a line
// that is already listed.

const mcpserverPath = modulePath + "/internal/platform/mcpserver"

// adminCredentialCalls are the mcpserver functions that refuse an admin
// credential; only internal/app's composer calls them for a served tool.
var adminCredentialCalls = []string{"RefuseAdminCredential", "HoldsAdminCredential"}

// edgeLine is the ARCHITECTURE.md bullet that lists the service edges.
const edgeLine = "**Services may depend on services, one way.**"

// isDomainRoot reports whether rel is a domain's root package, internal/<domain>.
func isDomainRoot(rel string) bool {
	return strings.HasPrefix(rel, "internal/") && strings.Count(rel, "/") == 1 && layerOf(rel) == lService
}

// isDomainInbound reports whether rel is a domain's inbound adapter, under internal/<domain>/in.
func isDomainInbound(rel string) bool {
	parts := strings.Split(rel, "/")
	return len(parts) >= 4 && parts[0] == "internal" && parts[2] == "in" && isDomainRoot("internal/"+parts[1])
}

// isMCPAdapter reports whether rel is a domain's MCP package, internal/<domain>/in/<name>mcp.
func isMCPAdapter(rel string) bool {
	return isDomainInbound(rel) && strings.Count(rel, "/") == 3 && strings.HasSuffix(path.Base(rel), "mcp")
}

// localName is the name f uses for the package at ip, or "" when f does
// not import it.
func localName(f *ast.File, ip string) string {
	for _, s := range f.Imports {
		if importPath(s) == ip {
			return importName(s)
		}
	}
	return ""
}

func recvType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func funcName(fd *ast.FuncDecl) string {
	if r := recvType(fd); r != "" {
		return r + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// toolSlice reports whether t is []<mcp>.Tool, []*<mcp>.Tool or a type of
// the package (named) declared as one of those.
func toolSlice(t ast.Expr, mcp string, named map[string]bool) bool {
	if id, ok := t.(*ast.Ident); ok {
		return named[id.Name]
	}
	at, ok := t.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	elt := at.Elt
	if st, ok := elt.(*ast.StarExpr); ok {
		elt = st.X
	}
	sel, ok := elt.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Tool" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && mcp != "" && x.Name == mcp
}

// returnsTools reports whether one of fd's results is a slice of tools, and
// whether that is the whole answer: exactly one plain []<mcp>.Tool.
func returnsTools(fd *ast.FuncDecl, mcp string, named map[string]bool) (tools, plain bool) {
	res := fd.Type.Results
	if res == nil {
		return false, false
	}
	for _, r := range res.List {
		if toolSlice(r.Type, mcp, named) {
			tools = true
		}
	}
	if !tools || len(res.List) != 1 || len(res.List[0].Names) > 1 {
		return tools, false
	}
	at, ok := res.List[0].Type.(*ast.ArrayType)
	if !ok {
		return true, false
	}
	_, ptr := at.Elt.(*ast.StarExpr)
	return true, !ptr
}

// toolSliceTypes are the package's own types declared as a slice of tools.
func toolSliceTypes(p *goPkg) map[string]bool {
	named := map[string]bool{}
	for _, f := range p.files {
		mcp := localName(f.ast, mcpserverPath)
		for _, d := range f.ast.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				if ts, ok := sp.(*ast.TypeSpec); ok && toolSlice(ts.Type, mcp, nil) {
					named[ts.Name.Name] = true
				}
			}
		}
	}
	return named
}

// takesMount reports whether fd's last parameter is a func named mount.
func takesMount(fd *ast.FuncDecl) bool {
	ps := fd.Type.Params.List
	if len(ps) == 0 {
		return false
	}
	last := ps[len(ps)-1]
	if _, ok := last.Type.(*ast.FuncType); !ok || len(last.Names) == 0 {
		return false
	}
	return last.Names[len(last.Names)-1].Name == "mount"
}

// isSetter reports whether fd, a method of a domain's Service, swaps a
// dependency on a built service: any exported Set* method, and an exported
// With*, Use* or Wire* method that assigns a field of its receiver.
func isSetter(fd *ast.FuncDecl) bool {
	name := fd.Name.Name
	if rest, ok := strings.CutPrefix(name, "Set"); ok && (rest == "" || ast.IsExported(rest)) {
		return true
	}
	builder := false
	for _, pre := range []string{"With", "Use", "Wire"} {
		if rest, ok := strings.CutPrefix(name, pre); ok && (rest == "" || ast.IsExported(rest)) {
			builder = true
		}
	}
	if !builder || fd.Body == nil || len(fd.Recv.List[0].Names) == 0 {
		return false
	}
	recv := fd.Recv.List[0].Names[0].Name
	assigns := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, l := range as.Lhs {
			if rootIdent(l) == recv {
				assigns = true
			}
		}
		return true
	})
	return assigns
}

// rootIdent is the name a selector chain such as s.deps.x starts from, or ""
// when e is not a field of a field.
func rootIdent(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	for {
		switch x := sel.X.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.SelectorExpr:
			sel = x
		case *ast.ParenExpr:
			if in, ok := x.X.(*ast.SelectorExpr); ok {
				sel = in
				continue
			}
			if id, ok := x.X.(*ast.Ident); ok {
				return id.Name
			}
			return ""
		case *ast.StarExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				return id.Name
			}
			return ""
		default:
			return ""
		}
	}
}

// silencesForbidigo matches a nolint directive that turns forbidigo off:
// one naming it in a list, naming all, or naming no linter.
var silencesForbidigo = regexp.MustCompile(`^//\s*nolint(\s|$|:[^\s/]*\b(forbidigo|all)\b)`)

// enclosing names the function of f that holds pos, or "package level".
func enclosing(f *ast.File, pos ast.Node) string {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Pos() <= pos.Pos() && pos.End() <= fd.End() {
			return funcName(fd)
		}
	}
	return "package level"
}

// shapeViolations returns today's breaks of the shape rules in the module at
// root, one "<package>: <finding>" line each, sorted.
func shapeViolations(root string) ([]string, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	count := map[string]int{}
	add := func(rel, format string, a ...any) { count[rel+": "+fmt.Sprintf(format, a...)]++ }
	for rel, p := range pkgs {
		for _, f := range p.files {
			for _, cg := range f.ast.Comments {
				for _, c := range cg.List {
					if silencesForbidigo.MatchString(c.Text) {
						add(rel, "%s: %s silences the uniqueid lint (generate ids with internal/lib/uniqueid)", f.name, enclosing(f.ast, c))
					}
				}
			}
		}
		isRoot, inbound, mcpPkg := isDomainRoot(rel), isDomainInbound(rel), isMCPAdapter(rel)
		if !isRoot && !inbound {
			continue
		}
		named := toolSliceTypes(p)
		for _, f := range p.files {
			mcp := localName(f.ast, mcpserverPath)
			for _, d := range f.ast.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if isRoot && recvType(fd) == "Service" && fd.Name.IsExported() && isSetter(fd) {
					add(rel, "%s: Service.%s sets a dependency on a built service (take it in New)", f.name, fd.Name.Name)
				}
				if !mcpPkg || !fd.Name.IsExported() {
					continue
				}
				if tools, plain := returnsTools(fd, mcp, named); tools && (!plain || fd.Name.Name != "Tools" || fd.Recv != nil || !takesMount(fd)) {
					add(rel, "%s: %s returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)", f.name, funcName(fd))
				}
			}
			if !inbound || mcp == "" {
				continue
			}
			ast.Inspect(f.ast, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !slices.Contains(adminCredentialCalls, sel.Sel.Name) {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == mcp {
					add(rel, "%s: %s uses mcpserver.%s (internal/app wraps every tool once)", f.name, enclosing(f.ast, sel), sel.Sel.Name)
				}
				return true
			})
		}
	}
	// A second finding of the same kind in the same function changes the
	// line, so it is never absorbed by one already in the baseline.
	out := make([]string, 0, len(count))
	for l, n := range count {
		if n > 1 {
			l += fmt.Sprintf(" (%d times)", n)
		}
		out = append(out, l)
	}
	slices.Sort(out)
	return out, nil
}

// serviceEdges returns the imports between domain root packages, as
// "from → to" lines, sorted.
func serviceEdges(root string) ([]string, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for rel, p := range pkgs {
		if !isDomainRoot(rel) {
			continue
		}
		for _, f := range p.files {
			for _, s := range f.ast.Imports {
				to, ok := strings.CutPrefix(importPath(s), modulePath+"/")
				if ok && to != rel && isDomainRoot(to) && pkgs[to] != nil {
					out = append(out, path.Base(rel)+" → "+path.Base(to))
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

var edgeGroup = regexp.MustCompile("`([a-z0-9]+)` → ((?:`[a-z0-9]+`(?:, )?)+)")

// parseServiceEdges reads the edge list from ARCHITECTURE.md's "Services may
// depend on services" bullet, as "from → to" lines, sorted.
func parseServiceEdges(file string) ([]string, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, edgeLine) {
			continue
		}
		var out []string
		for _, m := range edgeGroup.FindAllStringSubmatch(line, -1) {
			for _, to := range strings.Split(m[2], ",") {
				out = append(out, m[1]+" → "+strings.Trim(strings.TrimSpace(to), "`"))
			}
		}
		slices.Sort(out)
		return slices.Compact(out), nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s: no line holds %q", file, edgeLine)
}

func TestShapes(t *testing.T) {
	root := moduleRoot(t)
	got, err := shapeViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "internal", "testkit", "archtest", "shape_baseline.txt")
	var base []string
	if _, err := os.Stat(file); err == nil {
		base = readLines(t, file)
	}
	if *update {
		// -update only removes lines: a new violation is fixed, never listed.
		var keep []string
		for _, l := range base {
			if slices.Contains(got, l) {
				keep = append(keep, l)
			}
		}
		if len(keep) == 0 {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(file, []byte(strings.Join(keep, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		base = keep
	}
	for _, l := range got {
		if !slices.Contains(base, l) {
			t.Errorf("%s\n\tnew violation; fix it (do not add it to shape_baseline.txt)", l)
		}
	}
	for _, l := range base {
		if !slices.Contains(got, l) {
			t.Errorf("%s\n\tno longer violated; remove it from shape_baseline.txt (or run -update)", l)
		}
	}
}

func TestServiceEdgesMatchArchitecture(t *testing.T) {
	root := moduleRoot(t)
	want, err := parseServiceEdges(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := serviceEdges(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if !slices.Contains(want, e) {
			t.Errorf("service edge %s is not in ARCHITECTURE.md's list (%s): add it there, or remove the import", e, edgeLine)
		}
	}
	for _, e := range want {
		if !slices.Contains(got, e) {
			t.Errorf("ARCHITECTURE.md lists service edge %s, which the code no longer has: remove it from the list", e)
		}
	}
}

// TestShapeRulesCatchViolations runs the shape rules on a small module with a
// breach of each.
func TestShapeRulesCatchViolations(t *testing.T) {
	m := modulePath + "/"
	mcpImp := "import (\n\t\"context\"\n\t\"encoding/json\"\n\n\tsrv \"" + m + "internal/platform/mcpserver\"\n)\n\n"
	mountT := "func(string, func(context.Context, json.RawMessage) (any, error)) srv.Tool"
	files := map[string]string{
		"go.mod":                           "module " + modulePath + "\n",
		"internal/platform/mcpserver/m.go": "package mcpserver\n\ntype Tool struct{}\n\nfunc RefuseAdminCredential() {}\nfunc HoldsAdminCredential() bool { return false }\n",
		"internal/agent/s.go": "package agent\n\n" + imp(m+"internal/links", m+"internal/approval") + "type Service struct{ d any }\n\nfunc (s *Service) SetPorts() {}\nfunc (s Service) Settle() {}\nfunc (s *Service) setLate() {}\n" +
			"func (s *Service) WithDelivery(d any) { s.d = d }\nfunc (s Service) WireUp(d any) Service { (s).d = d; return s }\nfunc (s *Service) UseX() any { x := s.d; return x }\n",
		"internal/approval/s.go":  "package approval\n\n" + imp(m+"internal/links") + "type Service struct{}\n\nfunc (s *Service) Set() {}\n\ntype Other struct{}\n\nfunc (o *Other) SetX() {}\n",
		"internal/links/s.go":     "package links\n\n" + imp(m+"internal/links/sub") + "type Service struct{}\n",
		"internal/links/sub/s.go": "package sub\n\n" + imp(m+"internal/approval") + "type Service struct{}\n\nfunc (s *Service) SetX() {}\n",
		"internal/agent/in/agentmcp/t.go": "package agentmcp\n\n" + mcpImp + "func Tools(svc any, mount " + mountT + ") []srv.Tool { return nil }\nfunc RunTools(svc any, mount " + mountT + ") []srv.Tool { return nil }\nfunc helper(mount " + mountT + ") []srv.Tool { return nil }\n\nvar _ = srv.HoldsAdminCredential\n" +
			"var _ = srv.HoldsAdminCredential\n\nfunc Errs(mount " + mountT + ") ([]srv.Tool, error) { return nil, nil }\nfunc Ptrs(mount " + mountT + ") []*srv.Tool { return nil }\n\ntype List []srv.Tool\n\nfunc Named(mount " + mountT + ") List { return nil }\n",
		"internal/approval/in/approvalmcp/t.go":  "package approvalmcp\n\n" + mcpImp + "func Tools(svc any, wrap " + mountT + ") []srv.Tool { return nil }\n\ntype Down struct{}\n\nfunc (Down) Tools() []srv.Tool { srv.RefuseAdminCredential(); return nil }\n",
		"internal/approval/in/approvalpage/p.go": "package approvalpage\n\n" + mcpImp + "func Page(mount " + mountT + ") []srv.Tool { srv.RefuseAdminCredential(); return nil }\n",
		"internal/lib/ids/i.go":                  "package ids\n\nvar ID = 1 //nolint:forbidigo // probe\n\nfunc F() {\n\t_ = 1 //nolint:gosec,forbidigo // probe\n\t_ = 2 //nolint:gosec,forbidigo // probe\n\t_ = 3 //nolint:gosec // not forbidigo\n}\n\nfunc G() {\n\t_ = 1 //nolint:all // probe\n}\n",
		"internal/app/a.go":                      "package app\n\n" + mcpImp + "var _ = srv.RefuseAdminCredential\n",
		"ARCHITECTURE.md":                        "- " + edgeLine + " Today: `agent` → `approval`, `ledger`; `approval` → `links`. Go refuses a cycle.\n",
	}
	root := fixture(t, files)
	got, err := shapeViolations(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/agent/in/agentmcp: t.go: Errs returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/agent/in/agentmcp: t.go: Named returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/agent/in/agentmcp: t.go: Ptrs returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/agent/in/agentmcp: t.go: RunTools returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/agent/in/agentmcp: t.go: package level uses mcpserver.HoldsAdminCredential (internal/app wraps every tool once) (2 times)",
		"internal/agent: s.go: Service.SetPorts sets a dependency on a built service (take it in New)",
		"internal/agent: s.go: Service.WireUp sets a dependency on a built service (take it in New)",
		"internal/agent: s.go: Service.WithDelivery sets a dependency on a built service (take it in New)",
		"internal/approval/in/approvalmcp: t.go: Down.Tools returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/approval/in/approvalmcp: t.go: Down.Tools uses mcpserver.RefuseAdminCredential (internal/app wraps every tool once)",
		"internal/approval/in/approvalmcp: t.go: Tools returns []mcpserver.Tool (export one func Tools(port, mount) []mcpserver.Tool)",
		"internal/approval/in/approvalpage: p.go: Page uses mcpserver.RefuseAdminCredential (internal/app wraps every tool once)",
		"internal/approval: s.go: Service.Set sets a dependency on a built service (take it in New)",
		"internal/lib/ids: i.go: F silences the uniqueid lint (generate ids with internal/lib/uniqueid) (2 times)",
		"internal/lib/ids: i.go: G silences the uniqueid lint (generate ids with internal/lib/uniqueid)",
		"internal/lib/ids: i.go: package level silences the uniqueid lint (generate ids with internal/lib/uniqueid)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("shapeViolations:\n got %q\nwant %q", got, want)
	}

	edges, err := serviceEdges(root)
	if err != nil {
		t.Fatal(err)
	}
	if w := []string{"agent → approval", "agent → links", "approval → links"}; !slices.Equal(edges, w) {
		t.Errorf("serviceEdges: got %q, want %q", edges, w)
	}
	listed, err := parseServiceEdges(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if w := []string{"agent → approval", "agent → ledger", "approval → links"}; !slices.Equal(listed, w) {
		t.Errorf("parseServiceEdges: got %q, want %q", listed, w)
	}
}
