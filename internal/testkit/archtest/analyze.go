package archtest

import (
	"bufio"
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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
	lE2E      = "e2e"
)

// layerOrder lists the path prefixes of the layers outside the domain tree
// (newTree); the first match wins.
var layerOrder = []struct{ prefix, name string }{
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
	{lE2E, lE2E},
}

// allowed lists, per importing layer, the layers it may import. A layer that
// is not listed (app, testkit, scripts, e2e) may import anything.
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

// pkgForwards are the core packages a package under pkg/ imports on top of
// its layer's list, each edge by name: another program needs the engine's
// own trust code, so pkg/trustprofile and pkg/trustpin are aliases and
// forwards to it. A new edge fails, and so does a listed one the package
// no longer imports (TestPkgForwardsAreListed).
var pkgForwards = map[string][]string{
	"pkg/trustprofile": {"internal/core/trustprofile"},
	"pkg/trustpin":     {"internal/core/trustpin"},
}

// pkgDecisionForwards are the decision functions a package under pkg/ may
// call, as package -> decision package -> functions: pkg/trustpin forwards
// Check and Approved because another program's service runs the same pin
// check as the engine's. Any other call from pkg/ to a decision fails, and
// so does a listed one the package no longer makes
// (TestPkgDecisionForwardsAreListed). The forwards, of the same names, are
// for other modules: no package of this one but pkg/ and the dead code
// root calls them (TestDecisionForwardsOnlyForOtherModules).
var pkgDecisionForwards = map[string]map[string][]string{
	"pkg/trustpin": {"trustpin": {"Check", "Approved"}},
}

// pkgImportsAllowlist lists, as "<package>: <import>", the packages one
// package under pkg/ imports on top of its layer's list. pkg/setup is the
// second composition root: it forwards to the setup service and builds the
// setup adapter for a program that calls it directly. The list only
// shrinks.
//
//go:embed pkg_imports_allowlist.txt
var pkgImportsAllowlist string

// pkgExtra is pkgImportsAllowlist as a map from package to the imports it
// may make on top of its layer's list. pkgExtraProblems are the lines it
// could not take; TestPkgImportsAllowlistOnlyShrinks fails on each.
var pkgExtra, pkgExtraProblems = parsePkgImports(pkgImportsAllowlist)

// parsePkgImports reads the allowlist's "<package>: <import>" lines. A blank
// line is skipped. A line of another form, a package outside pkg/ or an
// empty import is a problem, never skipped: the allowlist widens only what
// a package under pkg/ may import.
func parsePkgImports(text string) (allow map[string][]string, problems []string) {
	allow = map[string][]string{}
	for i, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		pkg, target, ok := strings.Cut(l, ": ")
		pkg, target = strings.TrimSpace(pkg), strings.TrimSpace(target)
		switch {
		case !ok || pkg == "" || target == "":
			problems = append(problems, fmt.Sprintf("line %d: %q is not \"<package>: <import>\"", i+1, l))
		case !strings.HasPrefix(pkg, "pkg/"):
			problems = append(problems, fmt.Sprintf("line %d: %q names %s, which is not under pkg/", i+1, l, pkg))
		default:
			allow[pkg] = append(allow[pkg], target)
		}
	}
	return allow, problems
}

// domains are the domain folders under internal/.
var domains = []string{"agent", "approval", "engine", "handoff", "ledger", "links", "pii", "plugin", "revert", "setup", "status"}

// platformInbound are the platform packages that serve a transport; the rest
// of internal/platform are shared outbound adapters.
var platformInbound = []string{"httpserver", "mcpserver", "pageserver", "shim", "cli"}

// newTree lists the layer prefixes of the domain tree. They are tried before
// layerOrder, and in/ and out/ come before the domain root: the first match
// wins.
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

// testHelperRoots are the test helper trees that are not named for the
// package they fake: the shared test kit, and the notifier plugin the plugin
// transport's tests run.
var testHelperRoots = []string{
	"internal/testkit",
	"internal/plugin/out/plugintransport/testnotifier",
}

// testHelperBesides are the <x>test helpers that sit in a package other than
// <x>: the MCP server's test client, the Vault's page fake and the plugin
// adapters' test kit.
var testHelperBesides = []string{
	"internal/platform/mcpserver/mcptest",
	"internal/platform/vault/pagetest",
	"internal/plugin/out/plugintransport/adaptertest",
}

// isTestHelper reports whether the package at rel, among pkgs, is a test
// helper: a package only tests import (fakes, fixtures, the core test
// oracles). A helper sits under a testHelperRoots entry, or is named <x>test
// and sits in package <x> (x/xtest), or is a testHelperBesides entry; a
// package below a helper is one too. A program (package main, or anything
// under cmd/) is never a helper by its name. Helpers are exempt from the
// layer rules, core purity and the decision rule, and no other non-test file
// may import one.
func isTestHelper(pkgs map[string]*goPkg, rel string) bool {
	return testHelper(rel, func(p string) (bool, bool) {
		pk := pkgs[p]
		return pk != nil, pk != nil && isMain(pk)
	})
}

// isTestHelperFS is isTestHelper for the module tree in fsys, for checks
// that read a package graph rather than load the tree.
func isTestHelperFS(fsys fs.FS, rel string) bool {
	return testHelper(rel, func(p string) (bool, bool) {
		entries, err := fs.ReadDir(fsys, p)
		if err != nil {
			return false, false
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			src, err := fs.ReadFile(fsys, path.Join(p, n))
			if err != nil {
				return false, false
			}
			f, err := parser.ParseFile(token.NewFileSet(), n, src, parser.PackageClauseOnly)
			if err != nil {
				return false, false
			}
			return true, f.Name.Name == "main"
		}
		return false, false
	})
}

// testHelper is isTestHelper over pkg, which reports whether a path is a
// package of the tree and whether it is a program.
func testHelper(rel string, pkg func(string) (exists, main bool)) bool {
	for _, h := range testHelperRoots {
		if rel == h || strings.HasPrefix(rel, h+"/") {
			return true
		}
	}
	if rel == lCmd || strings.HasPrefix(rel, lCmd+"/") {
		return false
	}
	for p := rel; p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if namedHelper(p, pkg) {
			return true
		}
	}
	return false
}

// namedHelper reports whether the package at p is a helper by its name.
func namedHelper(p string, pkg func(string) (exists, main bool)) bool {
	exists, isProgram := pkg(p)
	if !exists || isProgram {
		return false
	}
	if in(testHelperBesides, p) {
		return true
	}
	base, parent := path.Base(p), path.Dir(p)
	x, ok := strings.CutSuffix(base, "test")
	parentExists, _ := pkg(parent)
	return ok && x != "" && path.Base(parent) == x && parentExists
}

// isMain reports whether pk is a program.
func isMain(pk *goPkg) bool {
	return len(pk.files) > 0 && pk.files[0].ast.Name.Name == "main"
}

// checkTestHelpers fails a testHelperRoots or testHelperBesides entry that
// is no package of the tree.
func checkTestHelpers(pkgs map[string]*goPkg) []string {
	var problems []string
	for _, h := range slices.Concat(testHelperRoots, testHelperBesides) {
		found := false
		for rel := range pkgs {
			if rel == h || strings.HasPrefix(rel, h+"/") {
				found = true
				break
			}
		}
		if !found {
			problems = append(problems, h+" is listed as a test helper but holds no package; remove it")
		}
	}
	return problems
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
		slices.Sort(lines)
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
			if isTestHelper(pkgs, rel) || strings.Contains(rel, "/testdata") {
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
				if isTestHelper(pkgs, target) {
					if layer != lScripts {
						v.add(rel, "imports "+target+" (a test helper: only test files import it)")
					}
					continue
				}
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
	tl := layerOf(target)
	if layer == lInbound && tl == lService && strings.HasPrefix(rel, "internal/platform/") {
		v.add(rel, "imports "+target+" (an internal/platform package imports no domain service)")
		return
	}
	if in(ok, tl) || in(pkgExtra[rel], target) || in(pkgForwards[rel], target) {
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

// pluginPkgs is the plugin domain, whose path rule only the app installs.
var pluginPkgs = []string{modulePath + "/internal/plugin"}

// appPkg is the package that wires everything.
const appPkg = "internal/app"

// checkPathRulesInstall flags a call to plugin.UsePathRules outside the
// app: the path rule is installed once, by the wiring. Test files are not
// loaded, so they may install it.
func checkPathRulesInstall(v violations, rel string, f *goFile) {
	names := localNames(f.ast)
	ast.Inspect(f.ast, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "UsePathRules" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && in(pluginPkgs, names[id.Name]) {
			v.add(rel, fmt.Sprintf("%s calls plugin.UsePathRules (only internal/app installs the path rule)", f.name))
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
		if in(pkgDecisionForwards[rel][dec], sel.Sel.Name) {
			return true
		}
		v.add(rel, fmt.Sprintf("%s calls %s.%s", f.name, dec, sel.Sel.Name))
		return true
	})
}

var bannedExact = []string{"os", ioFSPkg, "io/ioutil", "path/filepath", netPkg, "os/exec", "math/rand", "database/sql", "database/sql/driver", "syscall"}

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
	case pgParser(p):
		return true
	case p == "crypto/rand":
		return true
	}
	return false
}

// pgParserImports are the Postgres parser's modules (libpg_query and its
// pure-Go wasm build). Only the Postgres adapter parses Postgres SQL.
var pgParserImports = []string{"github.com/pganalyze/pg_query_go", "github.com/wasilibs/go-pgquery"}

// pgParser reports whether p is one of pgParserImports or below one.
func pgParser(p string) bool {
	return slices.ContainsFunc(pgParserImports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") })
}

// serviceBanned reports whether a service may not import p: a service reaches
// Postgres and the network through a port, never through the driver or a
// protocol client library itself. net/http's sub-packages (httptest,
// httputil and the rest) count too, and so do ConnectRPC
// (connectrpc.com/...), gRPC (google.golang.org/grpc/...) and the clients
// generated from the module's protos (an api/ package named <pkg>connect,
// such as connectv1connect). The proto messages themselves are not banned.
func serviceBanned(p string) bool {
	return p == "github.com/jackc/pgx" || strings.HasPrefix(p, "github.com/jackc/pgx/") ||
		p == "database/sql" || p == "net/http" || strings.HasPrefix(p, "net/http/") ||
		strings.HasPrefix(p, "connectrpc.com/") ||
		p == "google.golang.org/grpc" || strings.HasPrefix(p, "google.golang.org/grpc/") ||
		generatedConnectClient(p)
}

// generatedConnectClient reports whether p is a ConnectRPC client generated
// from one of the module's protos: a package under api/ whose last element is
// <pkg>connect (api/connect itself is the contract package, not a client).
func generatedConnectClient(p string) bool {
	if !strings.HasPrefix(p, modulePath+"/api/") {
		return false
	}
	last := p[strings.LastIndex(p, "/")+1:]
	return strings.HasSuffix(last, "connect") && last != "connect"
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
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		ip := names[id.Name]
		if ip == "time" && in([]string{"Now", "Since", "Until"}, sel.Sel.Name) {
			v.add(rel, f.name+" calls time."+sel.Sel.Name+" (core must stay pure)")
		}
		if only, limited := extraOnly[area][ip]; limited && in(extras, ip) && !in(only, sel.Sel.Name) {
			v.add(rel, fmt.Sprintf("%s uses %s.%s (the register grants %s for %s only)", f.name, ip, sel.Sel.Name, ip, strings.Join(only, ", ")))
		}
		return true
	})
}

// extraOnly limits an extra import of a core package to the names listed:
// setupcode may import net for net.JoinHostPort, and trustprofile net for
// net.ParseIP and io/fs for fs.FS, fs.ReadDir and fs.ReadFile, and nothing
// else of them.
var extraOnly = map[string]map[string][]string{
	coreSetupcode:    {netPkg: {"JoinHostPort"}},
	coreTrustprofile: {netPkg: {"ParseIP"}, ioFSPkg: {"FS", "ReadDir", "ReadFile"}},
}

// The core packages granted an extra import.
const (
	coreSetupcode    = "setupcode"
	coreTrustprofile = "trustprofile"
)

// netPkg is the standard library's net package.
const netPkg = "net"

// ioFSPkg is the standard library's io/fs package.
const ioFSPkg = "io/fs"

// extraAllowed reports whether the register may grant core package name the
// extra import e: crypto/rand for key and salt generation in channel and
// setupcode, net for setupcode's database address (net.JoinHostPort) and
// trustprofile's exact-address match entries (net.ParseIP), and io/fs for
// trustprofile's LoadFS, which reads the profiles of the fs.FS its caller
// gives.
func extraAllowed(name, e string) bool {
	switch e {
	case "crypto/rand":
		return name == "channel" || name == coreSetupcode
	case netPkg:
		return name == coreSetupcode || name == coreTrustprofile
	case ioFSPkg:
		return name == coreTrustprofile
	}
	return false
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
			if !extraAllowed(name, e) {
				problems = append(problems, fmt.Sprintf("register row %s: extra import %q is not allowed (only crypto/rand, only for channel and setupcode; net, only for setupcode and trustprofile; io/fs, only for trustprofile)", name, e))
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
	slices.Sort(problems)
	return problems
}
