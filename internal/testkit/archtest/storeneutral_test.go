package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// storeRule is what a store-neutral domain's root package (its non-test
// files) may not hold: imports of a store's packages, identifiers and
// string texts that name a store's own things, and selectors of the shared
// packages that read a store's answers.
type storeRule struct {
	dir     string
	imports []string
	ident   *regexp.Regexp
	text    *regexp.Regexp
	// selectors are, by import path, the names of that package the domain
	// may not use. They are matched on the selector, resolved through the
	// file's imports, so an alias does not hide one.
	selectors map[string]*regexp.Regexp
	// allowed are findings that may stay, each with its reason.
	allowed map[string]string
}

var storeBoundImports = []string{
	modulePath + "/internal/core/sqlguard",
	modulePath + "/internal/platform/postgres",
	"github.com/jackc/pgx",
	"github.com/jackc/pgconn",
}

// agentStoreRule holds internal/agent to its store's ports.
var agentStoreRule = storeRule{
	dir:     filepath.Join("internal", "agent"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`OID|Oid|Attnum|attnum|pg_`),
	text:    regexp.MustCompile(`\$[0-9]|pg_`),
	allowed: map[string]string{},
}

// revertStoreRule holds internal/revert to its store's ports: it decides on
// the store's typed refusals, never on the guard's codes, details or
// SQLSTATEs.
var revertStoreRule = storeRule{
	dir:     filepath.Join("internal", "revert"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`SQLState|OID|Oid|xmin|pg_`),
	// A SQLSTATE is five digits or capitals starting with a digit, such as
	// 57014; the domain reads the store's codes only through its ports.
	text: regexp.MustCompile(`pg_|xmin|\b[0-9][0-9A-Z]{4}\b`),
	selectors: map[string]*regexp.Regexp{
		modulePath + "/internal/core/guidance":   regexp.MustCompile(`^(LedgerCode|StoreDetail|ScopeRefusal|TimedOut)$`),
		modulePath + "/internal/core/guardmodel": regexp.MustCompile(`^(Code.*|Scope.*|.*Refused)$`),
		modulePath + "/internal/core/action":     regexp.MustCompile(`^StoreError$`),
	},
	allowed: map[string]string{
		"revert_steps.go: identifier SQLState": "the timeout answer's toolresult.ToolError still names the store's code " +
			"SQLState; renaming ToolError's field removes this entry",
	},
}

// importName is the name a file refers to the import s by.
func importName(s *ast.ImportSpec) string {
	if s.Name != nil {
		return s.Name.Name
	}
	p := importPath(s)
	name := path.Base(p)
	if len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
		name = path.Base(path.Dir(p))
	}
	return name
}

func storeNeutralFindings(dir string, rule storeRule) ([]string, int, error) {
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
		banned := map[string]*regexp.Regexp{}
		for _, s := range f.Imports {
			p := importPath(s)
			if slices.ContainsFunc(rule.imports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") }) {
				add("import " + p)
			}
			if re, ok := rule.selectors[p]; ok {
				banned[importName(s)] = re
			}
		}
		ast.Inspect(f, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.ImportSpec:
				return false // checked above
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok {
					if re, ok := banned[pkg.Name]; ok && re.MatchString(x.Sel.Name) {
						add("selector " + pkg.Name + "." + x.Sel.Name)
					}
				}
			case *ast.Ident:
				if rule.ident.MatchString(x.Name) {
					add("identifier " + x.Name)
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					break
				}
				if v, err := strconv.Unquote(x.Value); err == nil && rule.text.MatchString(v) {
					add("text " + x.Value)
				}
			}
			return true
		})
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

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

// requireStoreNeutral checks rule on the module's tree: it fails when it
// scans no file, on a finding the allowlist does not name, and on an
// allowlist entry with no reason or no finding.
func requireStoreNeutral(t *testing.T, rule storeRule, hint string) {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), rule.dir)
	findings, files, err := storeNeutralFindings(dir, rule)
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatalf("scanned no Go file in %s: the rule checks nothing", rule.dir)
	}
	for _, p := range checkStoreNeutral(findings, rule.allowed) {
		t.Errorf("%s: %s\n\t%s", rule.dir, p, hint)
	}
}

func TestAgentDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, agentStoreRule,
		"the agent domain reaches its store only through its ports; put store code in an adapter (internal/agent/out/...) or the wiring")
}

func TestRevertDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, revertStoreRule,
		"the revert domain reaches its store only through Records, Undo and Proofs and decides on action.RevertRefusalError; "+
			"map the store's answers in its adapter (for Postgres, internal/platform/postgres/store/revert.go)")
}

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
	findings, files, err := storeNeutralFindings(dir, agentStoreRule)
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

// The revert rule reads the shared packages' selectors through the file's
// imports, an alias too, and leaves the revert's own names alone: its
// refusal reasons, its scopes, and the guard's outcome and limit names.
func TestRevertStoreRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	"` + modulePath + `/internal/core/action"
	gm "` + modulePath + `/internal/core/guardmodel"
	"` + modulePath + `/internal/core/guidance"
	"` + modulePath + `/internal/core/revert"
	"` + modulePath + `/internal/core/toolresult"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	_ = gm.CodeScopeRefused
	_ = gm.ScopeShape
	_ = gm.RevertWidenRefused
	_ = guidance.LedgerCode
	_ = guidance.TimedOut
	_ *action.StoreError
	_ *pgconn.PgError
	_ = toolresult.ToolError{SQLState: "57014"}
	_ = "SELECT xmin FROM t"
	_ = "canceled (SQLSTATE 40P01)"

	// Allowed: the revert's own names.
	_ = guidance.CodeNotFound
	_ = gm.OutcomePending
	_ = gm.MaxRejectNote
	_ = action.RevertTimedOut
	_ = action.RevertWidenRefused
	_ = revert.ScopeRun
	_ *action.RevertRefusalError
	_ = "at most 20 runs and 1000 lines"
	_ = "id 123456, ref abc12345, version v0.1.0"
	_ = "0193b2c4-57a1-7c3e-9f2d-5e8a1b4c6d7f"
)

func scopeRefused() {}
func widenRefused() {}
`,
	})
	findings, files, err := storeNeutralFindings(dir, revertStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1", files)
	}
	want := []string{
		`a.go: identifier SQLState`,
		`a.go: import github.com/jackc/pgx/v5/pgconn`,
		`a.go: selector action.StoreError`,
		`a.go: selector gm.CodeScopeRefused`,
		`a.go: selector gm.RevertWidenRefused`,
		`a.go: selector gm.ScopeShape`,
		`a.go: selector guidance.LedgerCode`,
		`a.go: selector guidance.TimedOut`,
		`a.go: text "57014"`,
		`a.go: text "SELECT xmin FROM t"`,
		`a.go: text "canceled (SQLSTATE 40P01)"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
}
