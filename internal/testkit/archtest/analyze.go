package archtest

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const modulePath = "github.com/basaltdbhq/basaltdb"

// Kinds of core package, as written in the register.
const (
	kindDecision = "decision"
	kindTypes    = "types"
	kindCodec    = "codec"
)

const (
	lInbound  = "inbound"
	lOutbound = "outbound"
	lService  = "service"
	lCore     = "core"
	lLib      = "lib"
	lConfig   = "config"
	lApp      = "app"
	lTestkit  = "testkit"
	lCmd      = "cmd"
	lPkg      = "pkg"
	lApi      = "api"
	lWeb      = "web"
	lScripts  = "scripts"
)

// layerOrder lists the path prefixes of the layers; the first match wins.
var layerOrder = []struct{ prefix, name string }{
	{"internal/adapter/inbound", lInbound},
	{"internal/adapter/outbound", lOutbound},
	{"internal/service", lService},
	{"internal/core", lCore},
	{"internal/lib", lLib},
	{"internal/config", lConfig},
	{"internal/app", lApp},
	{"internal/testkit", lTestkit},
	{lCmd, lCmd},
	{lPkg, lPkg},
	{lApi, lApi},
	{lWeb, lWeb},
	{lScripts, lScripts},
}

// allowed lists, per importing layer, the layers it may import. A layer that
// is not listed (app, testkit, scripts) may import anything.
var allowed = map[string][]string{
	lLib:      {lLib},
	lCore:     {lCore, lLib, lApi},
	lConfig:   {lConfig, lCore, lLib, lApi},
	lService:  {lService, lConfig, lCore, lLib, lPkg, lApi},
	lOutbound: {lOutbound, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lInbound:  {lInbound, lService, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lCmd:      {lCmd, lApp, lService, lInbound, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lPkg:      {lPkg, lLib, lApi},
	lApi:      {lApi},
	lWeb:      {},
}

// pkgExtra lists layers that one package may import on top of its layer's list.
var pkgExtra = map[string][]string{
	"pkg/setup": {lService, lCore},
}

// storeSQLGuard is the one named exception to "only services call decisions":
// the Postgres store runs the SQL policy right before it runs SQL.
const (
	storePkg       = "internal/adapter/outbound/postgres/store"
	sqlguardPkg    = "sqlguard"
	storeCallsOnly = "Check CheckRepeatable"
)

func layerOf(rel string) string {
	for _, l := range layerOrder {
		if rel == l.prefix || strings.HasPrefix(rel, l.prefix+"/") {
			return l.name
		}
	}
	if strings.HasPrefix(rel, "internal/") {
		return "unknown"
	}
	return "other"
}

func isTestHelper(rel string) bool { return strings.HasSuffix(path.Base(rel), "test") }

// register is the parsed core register of ARCHITECTURE.md.
type register struct {
	rows map[string]regRow // by package name under internal/core
}

type regRow struct {
	area, kind, row string
	extras          []string // standard-library packages the row allows, e.g. crypto/rand
}

var regLine = regexp.MustCompile("^\\|\\s*`([a-z0-9]+)`\\s*\\|")

func parseRegister(file string) (*register, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &register{rows: map[string]regRow{}}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		m := regLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 5 {
			return nil, fmt.Errorf("register row for %s needs 5 cells (package, area, kind, admitted by, extras): %q", m[1], line)
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		row := regRow{area: cells[1], kind: cells[2], row: cells[3]}
		for _, e := range strings.Split(cells[4], ",") {
			if e = strings.Trim(strings.TrimSpace(e), "`"); e != "" && e != "-" {
				row.extras = append(row.extras, e)
			}
		}
		if _, dup := r.rows[m[1]]; dup {
			return nil, fmt.Errorf("register lists %s twice", m[1])
		}
		r.rows[m[1]] = row
	}
	return r, sc.Err()
}

// goPkg is one package of the module: its non-test files, parsed.
type goPkg struct {
	rel   string // path from the module root, "/" separated
	files []*goFile
}

type goFile struct {
	name string
	ast  *ast.File
}

// load parses every non-test Go file under root, ignoring build tags so the
// result does not depend on the OS it runs on.
func load(root string) (map[string]*goPkg, error) {
	pkgs := map[string]*goPkg{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root {
				if name == "testdata" || name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				if _, e := os.Stat(filepath.Join(p, "go.mod")); e == nil {
					return filepath.SkipDir // a nested module
				}
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if ignored(f) {
			return nil
		}
		dir, _ := filepath.Rel(root, filepath.Dir(p))
		dir = filepath.ToSlash(dir)
		pk := pkgs[dir]
		if pk == nil {
			pk = &goPkg{rel: dir}
			pkgs[dir] = pk
		}
		pk.files = append(pk.files, &goFile{name: name, ast: f})
		return nil
	})
	return pkgs, err
}

func ignored(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.TrimSpace(c.Text) == "//go:build ignore" {
				return true
			}
		}
	}
	return false
}

// violations maps an importing package to its sorted, de-duplicated violation lines.
type violations map[string][]string

func (v violations) add(pkg, line string) { v[pkg] = append(v[pkg], line) }

func (v violations) normalize() {
	for k, lines := range v {
		sort.Strings(lines)
		out := lines[:0]
		for i, l := range lines {
			if i == 0 || l != lines[i-1] {
				out = append(out, l)
			}
		}
		v[k] = out
	}
}

func importPath(s *ast.ImportSpec) string {
	p, _ := strconv.Unquote(s.Path.Value)
	return p
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// analyze checks the module at root against the rules and the register.
func analyze(root string, reg *register) (violations, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	v := violations{}
	decisions := map[string][]string{} // decision package name -> exported funcs
	for name, row := range reg.rows {
		if row.kind == kindDecision {
			decisions[name] = exportedFuncs(pkgs["internal/core/"+name])
		}
	}
	for rel, pk := range pkgs {
		layer := layerOf(rel)
		for _, f := range pk.files {
			if layer == lCore {
				checkPurity(v, reg, rel, f)
			}
			if isTestHelper(rel) || strings.Contains(rel, "/testdata") {
				continue
			}
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				if !strings.HasPrefix(ip, modulePath+"/") {
					continue
				}
				target := strings.TrimPrefix(ip, modulePath+"/")
				checkLayer(v, rel, layer, target)
			}
			if layer != lCore && layer != lService && layer != lTestkit && layer != lScripts {
				checkDecisionCalls(v, rel, f, decisions)
			}
		}
		if layer == "unknown" {
			v.add(rel, "package is under internal/ but not in a layer")
		}
	}
	v.normalize()
	return v, nil
}

func checkLayer(v violations, rel, layer, target string) {
	if isTestHelper(target) {
		return
	}
	ok, listed := allowed[layer]
	if !listed {
		return // app, testkit, scripts, other: no rule
	}
	extra := pkgExtra[rel]
	tl := layerOf(target)
	if in(ok, tl) || in(extra, tl) {
		return
	}
	v.add(rel, "imports "+target)
}

func exportedFuncs(pk *goPkg) []string {
	var out []string
	if pk == nil {
		return out
	}
	for _, f := range pk.files {
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.IsExported() {
				out = append(out, fd.Name.Name)
			}
		}
	}
	return out
}

// localNames maps the name a file uses for each import to the import path.
func localNames(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, s := range f.Imports {
		ip := importPath(s)
		n := path.Base(ip)
		if s.Name != nil {
			n = s.Name.Name
		}
		m[n] = ip
	}
	return m
}

func checkDecisionCalls(v violations, rel string, f *goFile, decisions map[string][]string) {
	names := localNames(f.ast)
	ast.Inspect(f.ast, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		ip, ok := names[id.Name]
		if !ok || !strings.HasPrefix(ip, modulePath+"/internal/core/") {
			return true
		}
		dec := strings.TrimPrefix(ip, modulePath+"/internal/core/")
		funcs, isDecision := decisions[dec]
		if !isDecision || !in(funcs, sel.Sel.Name) {
			return true
		}
		if rel == storePkg && dec == sqlguardPkg && in(strings.Fields(storeCallsOnly), sel.Sel.Name) {
			return true
		}
		v.add(rel, fmt.Sprintf("%s calls %s.%s", f.name, dec, sel.Sel.Name))
		return true
	})
}

var bannedExact = []string{"os", "io/fs", "path/filepath", "net", "os/exec", "math/rand", "database/sql"}

func bannedImport(p string) bool {
	switch {
	case in(bannedExact, p):
		return true
	case p == "net/url":
		return false
	case strings.HasPrefix(p, "net/"), strings.HasPrefix(p, "os/"):
		return true
	case strings.HasPrefix(p, "github.com/jackc/"), strings.HasPrefix(p, "github.com/lib/pq"), strings.HasPrefix(p, "math/rand/"):
		return true
	case p == "crypto/rand":
		return true
	}
	return false
}

func checkPurity(v violations, reg *register, rel string, f *goFile) {
	area := strings.SplitN(strings.TrimPrefix(rel, "internal/core/"), "/", 2)[0]
	extras := reg.rows[area].extras
	for _, s := range f.ast.Imports {
		ip := importPath(s)
		if bannedImport(ip) && !in(extras, ip) {
			v.add(rel, fmt.Sprintf("%s imports %s (core must stay pure)", f.name, ip))
		}
	}
	names := localNames(f.ast)
	ast.Inspect(f.ast, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] == "time" && sel.Sel.Name == "Now" {
			v.add(rel, f.name+" calls time.Now (core must stay pure)")
		}
		return true
	})
}

// checkRegister compares the register with the packages that exist.
func checkRegister(pkgs map[string]*goPkg, reg *register) []string {
	var problems []string
	exist := map[string]bool{}
	for rel := range pkgs {
		if strings.HasPrefix(rel, "internal/core/") {
			exist[strings.SplitN(strings.TrimPrefix(rel, "internal/core/"), "/", 2)[0]] = true
		}
	}
	for name := range exist {
		if _, ok := reg.rows[name]; !ok {
			problems = append(problems, fmt.Sprintf("internal/core/%s is not in the core register of ARCHITECTURE.md (a new core package needs a register row)", name))
		}
	}
	for name, row := range reg.rows {
		if !exist[name] {
			problems = append(problems, fmt.Sprintf("the register lists %s but internal/core/%s does not exist", name, name))
		}
		if !in([]string{kindDecision, kindTypes, kindCodec}, row.kind) {
			problems = append(problems, fmt.Sprintf("register row %s: kind %q must be decision, types or codec", name, row.kind))
		}
		if !in([]string{"1", "2", "3"}, row.row) {
			problems = append(problems, fmt.Sprintf("register row %s: admitted-by %q must be 1, 2 or 3", name, row.row))
		}
		if row.area == "" {
			problems = append(problems, fmt.Sprintf("register row %s: area is empty", name))
		}
	}
	sort.Strings(problems)
	return problems
}
