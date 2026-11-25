package archtest

import (
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

// The agent domain (the root package internal/agent) is store-neutral: it
// reaches its store only through the ports it declares, so it never imports
// a SQL or Postgres package and never writes a Postgres placeholder or
// catalog name (ARCHITECTURE.md, The agent domain is store-neutral).

// storeNeutralDir is the package the rule holds, from the module root.
var storeNeutralDir = filepath.Join("internal", "agent")

// storeBoundImports are import paths, or prefixes of them, a store-neutral
// package never imports.
var storeBoundImports = []string{
	modulePath + "/internal/core/sqlguard",
	modulePath + "/internal/platform/postgres",
	"github.com/jackc/pgx",
	"github.com/jackc/pgconn",
}

// storeBoundIdent matches an identifier that names a Postgres catalog
// thing: an OID, an attribute number, a pg_ name.
var storeBoundIdent = regexp.MustCompile(`OID|Oid|Attnum|attnum|pg_`)

// storeBoundText matches a string literal that holds a $n placeholder or a
// pg_ catalog name.
var storeBoundText = regexp.MustCompile(`\$[0-9]|pg_`)

// storeNeutralAllowed are the findings the rule lets pass, as
// "file: finding", each with the reason it may stay. An entry no finding
// uses fails the test, so the list cannot go stale.
var storeNeutralAllowed = map[string]string{}

// storeNeutralFindings parses the non-test Go files of dir and returns what
// breaks the rule, as "file: finding", and how many files it read.
func storeNeutralFindings(dir string) ([]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	files := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, 0, err
		}
		files++
		add := func(what string) { out = append(out, n+": "+what) }
		for _, s := range f.Imports {
			p := importPath(s)
			if slices.ContainsFunc(storeBoundImports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") }) {
				add("import " + p)
			}
		}
		ast.Inspect(f, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.ImportSpec:
				return false // checked above
			case *ast.Ident:
				if storeBoundIdent.MatchString(x.Name) {
					add("identifier " + x.Name)
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					break
				}
				if v, err := strconv.Unquote(x.Value); err == nil && storeBoundText.MatchString(v) {
					add("text " + x.Value)
				}
			}
			return true
		})
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

// checkStoreNeutral is the rule over findings: every finding not allowed
// with a reason fails, as does an allowed entry without a reason or no
// finding uses.
func checkStoreNeutral(findings []string, allowed map[string]string) []string {
	var out []string
	for _, f := range findings {
		if _, ok := allowed[f]; !ok {
			out = append(out, f)
		}
	}
	for entry, reason := range allowed {
		if strings.TrimSpace(reason) == "" {
			out = append(out, fmt.Sprintf("allowlist entry %q has no reason", entry))
		}
		if !slices.Contains(findings, entry) {
			out = append(out, fmt.Sprintf("allowlist entry %q matches nothing; remove it", entry))
		}
	}
	slices.Sort(out)
	return out
}

func TestAgentDomainIsStoreNeutral(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), storeNeutralDir)
	findings, files, err := storeNeutralFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatalf("scanned no Go file in %s: the rule checks nothing", storeNeutralDir)
	}
	for _, p := range checkStoreNeutral(findings, storeNeutralAllowed) {
		t.Errorf("%s: %s\n\tthe agent domain reaches its store only through its ports; put store code in an adapter (internal/agent/out/...) or the wiring", storeNeutralDir, p)
	}
}

// TestStoreNeutralRuleCatchesViolations runs the rule on a fixture: each
// kind of finding is caught, and the allowlist's own checks bite.
func TestStoreNeutralRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	_ "github.com/jackc/pgx/v5"
	_ "` + modulePath + `/internal/core/sqlguard"
	_ "` + modulePath + `/internal/platform/postgres/pgdial"
	_ "` + modulePath + `/internal/core/sqlguardian"
)

type ref struct{ TableOID uint32; attnum int16 }

const q = "SELECT x FROM t WHERE id = $1"
const c = "pg_catalog"
const fine = "costs $ 5"
`,
		"a_test.go": `package a

const ignored = "$1 pg_class"
`,
	})
	findings, files, err := storeNeutralFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1 (test files are left out)", files)
	}
	want := []string{
		`a.go: identifier TableOID`,
		`a.go: identifier attnum`,
		`a.go: import ` + modulePath + `/internal/core/sqlguard`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pgdial`,
		`a.go: import github.com/jackc/pgx/v5`,
		`a.go: text "SELECT x FROM t WHERE id = $1"`,
		`a.go: text "pg_catalog"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}

	allowed := map[string]string{
		`a.go: text "pg_catalog"`: "a reason",
		`a.go: identifier attnum`: " ",
		`a.go: gone`:              "it was removed",
	}
	got := checkStoreNeutral(findings, allowed)
	wantProblems := []string{
		`a.go: identifier TableOID`,
		`a.go: import ` + modulePath + `/internal/core/sqlguard`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pgdial`,
		`a.go: import github.com/jackc/pgx/v5`,
		`a.go: text "SELECT x FROM t WHERE id = $1"`,
		`allowlist entry "a.go: gone" matches nothing; remove it`,
		`allowlist entry "a.go: identifier attnum" has no reason`,
	}
	if !slices.Equal(got, wantProblems) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantProblems, "\n"))
	}
}
