package archtest

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The checks in this file keep internal/lib free of BasaltDB knowledge,
// internal/core free of mutable shared state, each domain's out/ adapters
// to that domain, and pkg/ to the public packages ARCHITECTURE.md names,
// holding forwards and types. Each has a baseline of what breaks the rule
// today: it only shrinks, and an entry that no longer breaks it fails.

// libKnowsBasaltBaseline lists the internal/lib string literals that name
// BasaltDB today, as "<package>: <declaration>".
var libKnowsBasaltBaseline = []string{
	"internal/lib/httpsec: ConnectPageCSP",
	"internal/lib/httpsec: PortalCSP",
	"internal/lib/logredact: secretForms",
}

// coreStateBaseline lists the exported core types that hold a mutex or a
// sync.Map today, as "<package>: <type>".
var coreStateBaseline = []string{
	"internal/core/chainpin: Memory",
	"internal/core/links: Secrets",
	"internal/core/pii: DictionaryBuild",
	"internal/core/pii: FuseDictionary",
}

// outImportExceptions are the named imports of a domain's out/ package from
// outside its owners, "<importer> -> <out package>", each with its reason.
var outImportExceptions = map[string]string{
	"internal/platform/postgres/agentcatalog -> internal/agent/out/sqllang": "the catalog reads tables with the agent's SQL parser; ARCHITECTURE.md keeps sqllang in the agent domain on purpose",
}

// outImportBaseline lists the imports of a domain's out/ package from
// outside its owners that break the rule today.
var outImportBaseline = []string{
	"internal/engine/out/binwatch -> internal/status/out/updatecheck",
	"internal/platform/osservice -> internal/plugin/out/pluginpath",
}

// pkgLogicBaseline lists the functions under pkg/ that are more than a
// forward today, as "<package>: <function>".
var pkgLogicBaseline = []string{
	"pkg/setup: (PasskeyRequest).Link",
	"pkg/setup: (PasskeyRequest).Verify",
	"pkg/setup: activePasskeys",
	"pkg/setup: adminAt",
	"pkg/setup: adminTx",
	"pkg/setup: asError",
	"pkg/setup: askPasskey",
	"pkg/setup: CertificateOf",
	"pkg/setup: Check",
	"pkg/setup: checkColumnClasses",
	"pkg/setup: checkColumnNames",
	"pkg/setup: checkLabels",
	"pkg/setup: CheckRemove",
	"pkg/setup: commitOutcome",
	"pkg/setup: ConnDatabase",
	"pkg/setup: ConnectedAs",
	"pkg/setup: describe",
	"pkg/setup: Describe",
	"pkg/setup: NewPasskeyRequest",
	"pkg/setup: newSetup",
	"pkg/setup: PasskeyRequestFor",
	"pkg/setup: pgxTx",
	"pkg/setup: printable",
	"pkg/setup: questions",
	"pkg/setup: recordTrustPin",
	"pkg/setup: registerInTx",
	"pkg/setup: requirePasskey",
	"pkg/setup: revokedLines",
	"pkg/setup: RevokePasskey",
	"pkg/setup: rollback",
	"pkg/setup: Run",
	"pkg/setup: RunRemove",
	"pkg/setup: sameTx",
	"pkg/setup: writeLabels",
	"pkg/trustpin: Approved",
	"pkg/trustpin: bidiControl",
	"pkg/trustpin: Check",
	"pkg/trustpin: clean",
	"pkg/trustpin: Fetch",
	"pkg/trustpin: IssuerOf",
	"pkg/trustpin: Name",
	"pkg/trustpin: publicChain",
	"pkg/trustpin: topName",
	"pkg/trustpin: ValidSHA256",
	"pkg/trustprofile: (*Profile).Certificates",
	"pkg/trustprofile: (*Profile).matchLen",
	"pkg/trustprofile: (*Set).For",
	"pkg/trustprofile: (*Set).Named",
	"pkg/trustprofile: (*Set).Replacing",
	"pkg/trustprofile: BuiltIns",
	"pkg/trustprofile: BuiltInSet",
	"pkg/trustprofile: CertificateNotVerified",
	"pkg/trustprofile: chainTo",
	"pkg/trustprofile: checkDNSName",
	"pkg/trustprofile: CheckFileName",
	"pkg/trustprofile: checkMatches",
	"pkg/trustprofile: checkNotPublic",
	"pkg/trustprofile: CheckOperatorMatch",
	"pkg/trustprofile: checkSource",
	"pkg/trustprofile: checkVerify",
	"pkg/trustprofile: DERSHA256",
	"pkg/trustprofile: exactOnly",
	"pkg/trustprofile: Explain",
	"pkg/trustprofile: FileSHA256",
	"pkg/trustprofile: Fingerprint",
	"pkg/trustprofile: init",
	"pkg/trustprofile: IsPublic",
	"pkg/trustprofile: LoadFS",
	"pkg/trustprofile: longest",
	"pkg/trustprofile: nameOf",
	"pkg/trustprofile: NewPin",
	"pkg/trustprofile: NewSet",
	"pkg/trustprofile: NormalizeMatch",
	"pkg/trustprofile: NormalizeSHA256",
	"pkg/trustprofile: Parse",
	"pkg/trustprofile: ParseCAs",
	"pkg/trustprofile: ParseCerts",
	"pkg/trustprofile: parseDisabled",
	"pkg/trustprofile: ProviderName",
	"pkg/trustprofile: PublicRoots",
	"pkg/trustprofile: readRoot",
	"pkg/trustprofile: readRoots",
	"pkg/trustprofile: SetSystemRootsForTest",
	"pkg/trustprofile: Trust",
	"pkg/trustprofile: uniqueByName",
	"pkg/trustprofile: VerifyFullByDefault",
	"pkg/trustprofile: withSystem",
	"pkg/trustprofile/trustprofiletest: Chain",
	"pkg/trustprofile/trustprofiletest: errorResponse",
	"pkg/trustprofile/trustprofiletest: PEM",
	"pkg/trustprofile/trustprofiletest: Profile",
	"pkg/trustprofile/trustprofiletest: readStartup",
	"pkg/trustprofile/trustprofiletest: serve",
	"pkg/trustprofile/trustprofiletest: Serve",
	"pkg/trustprofile/trustprofiletest: Set",
}

// basaltLiteral matches a string that names BasaltDB: the name itself, in
// any case, or one of its /v1/ API paths.
var basaltLiteral = regexp.MustCompile(`(?i)basalt|/v1/`)

// declName is the name of the top-level declaration n sits in: a function,
// a method as (T).Name or (*T).Name, or the first name of a const, var or
// type spec.
func declName(d ast.Decl, n ast.Node) string {
	switch d := d.(type) {
	case *ast.FuncDecl:
		return funcName(d)
	case *ast.GenDecl:
		for _, s := range d.Specs {
			if s.Pos() > n.Pos() || n.End() > s.End() {
				continue
			}
			switch s := s.(type) {
			case *ast.ValueSpec:
				return s.Names[0].Name
			case *ast.TypeSpec:
				return s.Name.Name
			}
		}
	}
	return "?"
}

// funcName is fd's name, with its receiver type for a method.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	star := ""
	if s, ok := t.(*ast.StarExpr); ok {
		star, t = "*", s.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return "(" + star + id.Name + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

// libLiteralsNamingBasalt returns, for every package under internal/lib, the
// declarations whose string literals name BasaltDB. Comments are not
// literals; test files are not loaded.
func libLiteralsNamingBasalt(pkgs map[string]*goPkg) []string {
	var out []string
	for rel, pk := range pkgs {
		if layerOf(rel) != lLib {
			continue
		}
		for _, f := range pk.files {
			for _, d := range f.ast.Decls {
				ast.Inspect(d, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						s = lit.Value
					}
					if basaltLiteral.MatchString(s) {
						out = append(out, rel+": "+declName(d, lit))
					}
					return true
				})
			}
		}
	}
	return sortedUnique(out)
}

// syncState reports whether the type expression t is a sync.Mutex,
// sync.RWMutex or sync.Map, or a pointer to one, given the file's import
// names. sync.Once is not state: it builds a table once.
func syncState(t ast.Expr, names map[string]string) bool {
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || names[id.Name] != "sync" {
		return false
	}
	return in([]string{"Mutex", "RWMutex", "Map"}, sel.Sel.Name)
}

// coreTypesWithState returns the exported types under internal/core whose
// struct, or a struct nested in it, has a mutex or sync.Map field.
func coreTypesWithState(pkgs map[string]*goPkg) []string {
	var out []string
	for rel, pk := range pkgs {
		if layerOf(rel) != lCore {
			continue
		}
		for _, f := range pk.files {
			names := localNames(f.ast)
			for _, d := range f.ast.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, s := range gd.Specs {
					ts := s.(*ast.TypeSpec)
					if !ts.Name.IsExported() {
						continue
					}
					found := false
					ast.Inspect(ts.Type, func(n ast.Node) bool {
						if fld, ok := n.(*ast.Field); ok && syncState(fld.Type, names) {
							found = true
						}
						return !found
					})
					if found {
						out = append(out, rel+": "+ts.Name.Name)
					}
				}
			}
		}
	}
	return sortedUnique(out)
}

// outOwner is the domain whose out/ adapter rel is, or "".
func outOwner(rel string) string {
	for _, d := range domains {
		p := "internal/" + d + "/out"
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return d
		}
	}
	return ""
}

// mayImportOut reports whether importer may import an out/ package of
// domain d: the domain itself, the wiring (internal/app and pkg/setup,
// the second composition root) and the test kit.
func mayImportOut(importer, d string) bool {
	for _, p := range []string{"internal/" + d, appPkg, "pkg/setup", "internal/testkit"} {
		if importer == p || strings.HasPrefix(importer, p+"/") {
			return true
		}
	}
	return false
}

// outImportsAcrossOwners returns every import of a domain's out/ package
// from a package that does not own it, as "<importer> -> <out package>".
func outImportsAcrossOwners(pkgs map[string]*goPkg) []string {
	var out []string
	for rel, pk := range pkgs {
		for _, f := range pk.files {
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				if !strings.HasPrefix(ip, modulePath+"/") {
					continue
				}
				target := strings.TrimPrefix(ip, modulePath+"/")
				if d := outOwner(target); d != "" && !mayImportOut(rel, d) {
					out = append(out, rel+" -> "+target)
				}
			}
		}
	}
	return sortedUnique(out)
}

// forward reports whether fd is no more than a forward: an empty body, or
// one statement that returns or calls, with no branch, loop or assignment.
func forward(fd *ast.FuncDecl) bool {
	if fd.Body == nil || len(fd.Body.List) == 0 {
		return true
	}
	if len(fd.Body.List) > 1 {
		return false
	}
	switch s := fd.Body.List[0].(type) {
	case *ast.ReturnStmt:
		return !hasFuncLit(s)
	case *ast.ExprStmt:
		return !hasFuncLit(s)
	}
	return false
}

// hasFuncLit reports whether n holds a function literal: logic in a forward.
func hasFuncLit(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			found = true
		}
		return !found
	})
	return found
}

// pkgLogic returns every function under pkg/ that is more than a forward,
// as "<package>: <function>". A package-level var whose value is a function
// literal counts as a function.
func pkgLogic(pkgs map[string]*goPkg) []string {
	var out []string
	for rel, pk := range pkgs {
		if layerOf(rel) != lPkg {
			continue
		}
		for _, f := range pk.files {
			for _, d := range f.ast.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if !forward(d) {
						out = append(out, rel+": "+funcName(d))
					}
				case *ast.GenDecl:
					for _, s := range d.Specs {
						if vs, ok := s.(*ast.ValueSpec); ok && hasFuncLit(vs) {
							out = append(out, rel+": "+vs.Names[0].Name)
						}
					}
				}
			}
		}
	}
	return sortedUnique(out)
}

// pkgListLine is ARCHITECTURE.md's tree line for pkg/, which names the
// packages in parentheses.
var pkgListLine = regexp.MustCompile(`^pkg/\s.*\(([^)]*)\)`)

// documentedPkgs returns the packages ARCHITECTURE.md's tree line for pkg/
// names.
func documentedPkgs(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := pkgListLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		var out []string
		for _, p := range strings.Split(m[1], ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		slices.Sort(out)
		return out, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s has no tree line for pkg/ naming its packages in parentheses", file)
}

func sortedUnique(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// compareBaseline fails on an entry got has and the baseline does not (a
// new break: fix it), and on a baseline entry got no longer has (fixed:
// remove it from the baseline).
func compareBaseline(t *testing.T, rule, fix string, got, baseline []string) {
	t.Helper()
	for _, g := range got {
		if !in(baseline, g) {
			t.Errorf("%s: %s\n\t%s (do not add it to the baseline)", rule, g, fix)
		}
	}
	for _, b := range baseline {
		if !in(got, b) {
			t.Errorf("%s: baseline entry %q no longer breaks the rule; remove it from the baseline", rule, b)
		}
	}
}

func loadModule(t *testing.T) (string, map[string]*goPkg) {
	t.Helper()
	root := moduleRoot(t)
	pkgs, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, pkgs
}

// TestLibKnowsNoBasalt fails on a string literal in internal/lib that names
// BasaltDB or one of its /v1/ paths: lib helpers know nothing of BasaltDB.
func TestLibKnowsNoBasalt(t *testing.T) {
	_, pkgs := loadModule(t)
	compareBaseline(t, "a string literal in internal/lib names BasaltDB",
		"move the value to the package that owns it and pass it in",
		libLiteralsNamingBasalt(pkgs), libKnowsBasaltBaseline)
}

// TestCoreHoldsNoState fails on an exported core type with a sync.Mutex,
// sync.RWMutex or sync.Map field: core is types, decisions and codecs, and
// state belongs to a service or an adapter. sync.Once is allowed.
func TestCoreHoldsNoState(t *testing.T) {
	_, pkgs := loadModule(t)
	compareBaseline(t, "an exported core type holds mutable shared state",
		"move the type to the domain or adapter that owns the state",
		coreTypesWithState(pkgs), coreStateBaseline)
}

// TestOutAdaptersStayInTheirDomain fails when a package of
// internal/<domain>/out is imported by anything but its domain,
// internal/app, pkg/setup, the test kit and the named exceptions.
func TestOutAdaptersStayInTheirDomain(t *testing.T) {
	_, pkgs := loadModule(t)
	got := outImportsAcrossOwners(pkgs)
	var rest []string
	for _, g := range got {
		if _, ok := outImportExceptions[g]; !ok {
			rest = append(rest, g)
		}
	}
	for e := range outImportExceptions {
		if !in(got, e) {
			t.Errorf("named exception %q is no longer imported; remove it", e)
		}
	}
	compareBaseline(t, "a domain's out/ adapter is imported from outside the domain",
		"move the adapter to internal/platform, or the shared value to core, or import it in internal/app and pass it in",
		rest, outImportBaseline)
}

// TestPkgIsTheDocumentedPublicAPI fails when the directories under pkg/
// differ from the packages ARCHITECTURE.md names for it, and on a function
// under pkg/ that is more than a forward: the logic lives under internal/.
func TestPkgIsTheDocumentedPublicAPI(t *testing.T) {
	root, pkgs := loadModule(t)
	want, err := documentedPkgs(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, lPkg))
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, e := range entries {
		if e.IsDir() {
			have = append(have, e.Name())
		}
	}
	if !slices.Equal(have, want) {
		t.Errorf("the packages under pkg/ are %q; ARCHITECTURE.md names %q. pkg/ is public API: add a package only with the line in ARCHITECTURE.md", have, want)
	}
	compareBaseline(t, "a function under pkg/ is more than a forward",
		"put the logic under internal/ and forward to it",
		pkgLogic(pkgs), pkgLogicBaseline)
}

// parsePkgs parses the given sources, keyed "<package path>/<file>", into
// packages as load does.
func parsePkgs(t *testing.T, src map[string]string) map[string]*goPkg {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string]*goPkg{}
	for p, s := range src {
		f, err := parser.ParseFile(fset, p, s, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.ToSlash(filepath.Dir(p))
		if pkgs[dir] == nil {
			pkgs[dir] = &goPkg{rel: dir}
		}
		pkgs[dir].files = append(pkgs[dir].files, &goFile{name: filepath.Base(p), ast: f})
	}
	return pkgs
}

func wantList(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: got %q, want %q", what, got, want)
	}
}

// TestPurityRulesOnProbes runs each rule on small sources: one that breaks
// it and one that does not.
func TestPurityRulesOnProbes(t *testing.T) {
	pkgs := parsePkgs(t, map[string]string{
		"internal/lib/probe/a.go": `package probe
// Package probe is used by basalt mcp: a comment is not a literal.
const Origin = "https://relay.BasaltVault.app"
var path = "/api/v1/links/"
func Build() string { return "/v1/runs" }
func (p *T) Plain() string { return "generic" }
type T struct{ Tag string ` + "`json:\"basalt\"`" + ` }
`,
		"internal/platform/clean/a.go": `package clean
const Origin = "https://basalt.example"
`,
	})
	wantList(t, "lib literals", libLiteralsNamingBasalt(pkgs), []string{
		"internal/lib/probe: Build",
		"internal/lib/probe: Origin",
		"internal/lib/probe: T",
		"internal/lib/probe: path",
	})

	pkgs = parsePkgs(t, map[string]string{
		"internal/core/probe/a.go": `package probe
import (
	"sync"
	s2 "sync"
)
type Locked struct{ mu sync.Mutex }
type RLocked struct{ mu *s2.RWMutex }
type Mapped struct{ inner struct{ m sync.Map } }
type Embedded struct{ sync.Mutex }
type Once struct{ once sync.Once }
type unexported struct{ mu sync.Mutex }
`,
		"internal/agent/probe/a.go": `package probe
import "sync"
type Service struct{ mu sync.Mutex }
`,
	})
	wantList(t, "core state", coreTypesWithState(pkgs), []string{
		"internal/core/probe: Embedded",
		"internal/core/probe: Locked",
		"internal/core/probe: Mapped",
		"internal/core/probe: RLocked",
	})

	imp := func(ps ...string) string {
		var b strings.Builder
		b.WriteString("package p\nimport (\n")
		for _, p := range ps {
			b.WriteString("\t_ \"" + modulePath + "/" + p + "\"\n")
		}
		b.WriteString(")\n")
		return b.String()
	}
	pkgs = parsePkgs(t, map[string]string{
		"internal/agent/a.go":               imp("internal/agent/out/sqllang"),
		"internal/agent/in/mcp/a.go":        imp("internal/agent/out/sqllang"),
		"internal/app/a.go":                 imp("internal/ledger/out/pinfile"),
		"internal/app/servedagent/a.go":     imp("internal/agent/out/sqllang"),
		"pkg/setup/a.go":                    imp("internal/setup/out/credfiles"),
		"internal/testkit/x/a.go":           imp("internal/setup/out/credfiles"),
		"internal/agentx/a.go":              imp("internal/agent/out/sqllang"),
		"internal/engine/out/binwatch/a.go": imp("internal/status/out/updatecheck"),
		"internal/platform/p/a.go":          imp("internal/plugin/out", "internal/core/links"),
		"pkg/trustpin/a.go":                 imp("internal/setup/out/credfiles"),
	})
	wantList(t, "out imports", outImportsAcrossOwners(pkgs), []string{
		"internal/agentx -> internal/agent/out/sqllang",
		"internal/engine/out/binwatch -> internal/status/out/updatecheck",
		"internal/platform/p -> internal/plugin/out",
		"pkg/trustpin -> internal/setup/out/credfiles",
	})

	pkgs = parsePkgs(t, map[string]string{
		"pkg/probe/a.go": `package probe
type T struct{}
func Forward(x int) int { return impl(x) }
func Call() { impl(1) }
func Empty() {}
func (t *T) Method() error { return nil }
func Branch(x int) int { if x > 0 { return 1 }; return 0 }
func Two() int { a := 1; return a }
func Loop() { for {} }
func Closure() func() { return func() { impl(2) } }
var hook = func() {}
var plain = 3
`,
		"internal/setup/a.go": `package setup
func Logic(x int) int { if x > 0 { return 1 }; return 0 }
`,
	})
	wantList(t, "pkg logic", pkgLogic(pkgs), []string{
		"pkg/probe: Branch",
		"pkg/probe: Closure",
		"pkg/probe: Loop",
		"pkg/probe: Two",
		"pkg/probe: hook",
	})
}

// TestDocumentedPkgsParsesTheTreeLine reads the pkg/ line's list and fails
// when the line is missing.
func TestDocumentedPkgsParsesTheTreeLine(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.md")
	if err := os.WriteFile(good, []byte("```\ninternal/lib/   helpers\npkg/       public Go API: only what other repos import (setup, trustprofile, trustpin)\n```\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := documentedPkgs(good)
	if err != nil {
		t.Fatal(err)
	}
	wantList(t, "documented pkgs", got, []string{"setup", "trustpin", "trustprofile"})
	bad := filepath.Join(dir, "bad.md")
	if err := os.WriteFile(bad, []byte("no tree here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := documentedPkgs(bad); err == nil {
		t.Error("a file with no pkg/ tree line must fail")
	}
}
