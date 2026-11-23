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
	lService:  {lService, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lOutbound: {lOutbound, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lInbound:  {lInbound, lService, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lCmd:      {lCmd, lApp, lService, lInbound, lConfig, lCore, lLib, lPkg, lApi, lWeb},
	lPkg:      {lPkg, lLib},
	lApi:      {lApi},
	lWeb:      {lCore, lLib},
}

// pkgExtra lists layers that one package may import on top of its layer's list.
// pkg/setup is the second composition root: it builds the adapters for a
// program that calls it directly.
var pkgExtra = map[string][]string{
	"pkg/setup": {lService, lCore, lOutbound},
}

// storeSQLGuard is the one named exception to "only services call decisions":
// the Postgres store runs the SQL policy right before it runs SQL.
const (
	sqlguardPkg    = "sqlguard"
	storeCallsOnly = "Check CheckRepeatable WithRowVersions"
)

// storePkgs is the Postgres store, at its old and its new path.
var storePkgs = []string{"internal/adapter/outbound/postgres/store", "internal/platform/postgres/store"}

// domains are the domain folders of the new tree (DESIGN-RESULTS, option B).
var domains = []string{"agent", "approval", "engine", "handoff", "ledger", "links", "pii", "plugin", "revert", "setup", "status"}

// platformInbound are the platform packages that serve a transport; the rest
// of internal/platform are shared outbound adapters.
var platformInbound = []string{"httpserver", "mcpserver", "pageserver", "shim", "cli"}

// newTree lists the layer prefixes of the new tree. They are tried before
// layerOrder, and in/ and out/ come before the domain root: the first match
// wins. The old prefixes stay in layerOrder while packages move.
var newTree = func() []struct{ prefix, name string } {
	type pl = struct{ prefix, name string }
	l := make([]pl, 0, len(platformInbound)+1+3*len(domains))
	for _, p := range platformInbound {
		l = append(l, pl{"internal/platform/" + p, lInbound})
	}
	l = append(l, pl{"internal/platform", lOutbound})
	for _, d := range domains {
		l = append(l, pl{"internal/" + d + "/in", lInbound}, pl{"internal/" + d + "/out", lOutbound}, pl{"internal/" + d, lService})
	}
	return l
}()

func layerOf(rel string) string {
	for _, l := range newTree {
		if rel == l.prefix || strings.HasPrefix(rel, l.prefix+"/") {
			return l.name
		}
	}
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

// testHelpers lists the packages that only tests import: fakes and fixtures.
// They are exempt from the layer rules, core purity and the decision rule.
var testHelpers = []string{
	"internal/testkit/archtest",
	"internal/testkit/connecttest",
	"internal/core/passkey/passkeytest",
	"internal/platform/mcpserver/mcptest",
	"internal/adapter/outbound/plugintransport/adaptertest",
	"internal/platform/vault/vaulttest",
	"internal/platform/vault/pagetest",
	"internal/adapter/outbound/postgres/guard/guardtest",
	"pkg/trustprofile/trustprofiletest",
	// the core test oracles (D-CORE-DEAD): signing and parsing clients
	// other packages' tests use
	"internal/core/approval/approvaltest",
	"internal/core/channel/channeltest",
	"internal/core/linkcodec/linkcodectest",
	"internal/core/links/linkstest",
	"internal/core/revert/reverttest",
	// the same helpers in the new tree
	"internal/platform/mcpserver/mcptest",
	"internal/plugin/out/plugintransport/adaptertest",
	"internal/platform/vault/vaulttest",
	"internal/platform/vault/pagetest",
	"internal/platform/postgres/guard/guardtest",
}

func isTestHelper(rel string) bool {
	for _, h := range testHelpers {
		if rel == h || strings.HasPrefix(rel, h+"/") {
			return true
		}
	}
	return false
}

// register is the parsed core register of ARCHITECTURE.md.
type register struct {
	rows map[string]regRow // by package name under internal/core
}

type regRow struct {
	area, kind, row string
	extras          []string // standard-library packages the row allows, e.g. crypto/rand
	codecs          []string // functions of a decision package that decode, parse or validate a format; any layer may call them
}

// regCells is the number of columns in a register row.
const regCells = 6

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
		if len(cells) < regCells {
			return nil, fmt.Errorf("register row for %s needs 6 cells (package, area, kind, admitted by, extras, codec functions): %q", m[1], line)
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
		for _, c := range strings.Split(cells[5], ",") {
			if c = strings.Trim(strings.TrimSpace(c), "`"); c != "" && c != "-" {
				row.codecs = append(row.codecs, c)
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
			for _, fn := range exportedFuncs(pkgs["internal/core/"+name]) {
				if !in(row.codecs, fn) {
					decisions[name] = append(decisions[name], fn)
				}
			}
		}
	}
	for rel, pk := range pkgs {
		layer := layerOf(rel)
		for _, f := range pk.files {
			if isTestHelper(rel) || strings.Contains(rel, "/testdata") {
				continue
			}
			if layer == lCore {
				checkPurity(v, reg, rel, f)
			}
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				if !strings.HasPrefix(ip, modulePath+"/") {
					continue
				}
				target := strings.TrimPrefix(ip, modulePath+"/")
				checkLayer(v, rel, layer, target)
			}
			if layer == lService {
				checkServiceImports(v, rel, f)
			}
			if rel != appPkg {
				checkPathRulesInstall(v, rel, f)
			}
			if layer == lInbound || layer == lOutbound || layer == lCmd || layer == lPkg || layer == lWeb {
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

// pluginhostPkgs is the plugin host, whose path rule only the app installs,
// at its old and its new path.
var pluginhostPkgs = []string{modulePath + "/internal/service/pluginhost", modulePath + "/internal/plugin"}

// appPkg is the package that wires everything.
const appPkg = "internal/app"

// checkPathRulesInstall flags a call to pluginhost.UsePathRules outside the
// app: the path rule is installed once, by the wiring. Test files are not
// loaded, so they may install it.
func checkPathRulesInstall(v violations, rel string, f *goFile) {
	names := localNames(f.ast)
	ast.Inspect(f.ast, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "UsePathRules" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && in(pluginhostPkgs, names[id.Name]) {
			v.add(rel, fmt.Sprintf("%s calls pluginhost.UsePathRules (only internal/app installs the path rule)", f.name))
		}
		return true
	})
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
		if in(storePkgs, rel) && dec == sqlguardPkg && in(strings.Fields(storeCallsOnly), sel.Sel.Name) {
			return true
		}
		v.add(rel, fmt.Sprintf("%s calls %s.%s", f.name, dec, sel.Sel.Name))
		return true
	})
}

var bannedExact = []string{"os", "io/fs", "io/ioutil", "path/filepath", "net", "os/exec", "math/rand", "database/sql", "database/sql/driver", "syscall"}

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

// serviceBanned reports whether a service may not import p: a service reaches
// Postgres and the network through a port, never through the driver itself.
func serviceBanned(p string) bool {
	return p == "github.com/jackc/pgx" || strings.HasPrefix(p, "github.com/jackc/pgx/") ||
		p == "database/sql" || p == "net/http"
}

func checkServiceImports(v violations, rel string, f *goFile) {
	for _, s := range f.ast.Imports {
		if ip := importPath(s); serviceBanned(ip) {
			v.add(rel, fmt.Sprintf("%s imports %s (a service reaches the database and the network through a port)", f.name, ip))
		}
	}
}

func checkPurity(v violations, reg *register, rel string, f *goFile) {
	area := strings.SplitN(strings.TrimPrefix(rel, "internal/core/"), "/", 2)[0]
	extras := reg.rows[area].extras
	for _, s := range f.ast.Imports {
		ip := importPath(s)
		if s.Name != nil && s.Name.Name == "." {
			v.add(rel, fmt.Sprintf("%s dot-imports %s (not allowed in core)", f.name, ip))
		}
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
		if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] == "time" && in([]string{"Now", "Since", "Until"}, sel.Sel.Name) {
			v.add(rel, f.name+" calls time."+sel.Sel.Name+" (core must stay pure)")
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
		for _, e := range row.extras {
			if e != "crypto/rand" || (name != "channel" && name != "setupcode") {
				problems = append(problems, fmt.Sprintf("register row %s: extra import %q is not allowed (only crypto/rand, only for channel and setupcode)", name, e))
			}
		}
		if len(row.codecs) > 0 && row.kind != kindDecision {
			problems = append(problems, fmt.Sprintf("register row %s: codec functions are listed only for a decision package", name))
		}
		have := exportedFuncs(pkgs["internal/core/"+name])
		for _, c := range row.codecs {
			if !in(have, c) {
				problems = append(problems, fmt.Sprintf("register row %s: codec function %q is not an exported function of internal/core/%s", name, c, name))
			}
		}
		if row.area == "" {
			problems = append(problems, fmt.Sprintf("register row %s: area is empty", name))
		}
	}
	sort.Strings(problems)
	return problems
}
