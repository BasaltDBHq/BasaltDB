package archtest

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The rules in this file keep codes, formats, limits and wire spellings in
// one home. Each scans the module's non-test Go files; what breaks a rule
// today is in its allowlist, with the reason, and an entry that no longer
// matches fails, so the lists only shrink.

var (
	treeOnce sync.Once
	treePkgs map[string]*goPkg
	errTree  error
)

// moduleTree parses the module once for the rules in this file.
func moduleTree(t *testing.T) map[string]*goPkg {
	t.Helper()
	treeOnce.Do(func() { treePkgs, errTree = load(moduleRoot(t)) })
	if errTree != nil {
		t.Fatal(errTree)
	}
	return treePkgs
}

// eachFile calls fn on every parsed file outside generated code, with its
// path from the module root and the file's import names.
func eachFile(pkgs map[string]*goPkg, fn func(rel, file string, f *ast.File, imports map[string]string)) int {
	files := 0
	for rel, pk := range pkgs {
		for _, f := range pk.files {
			if ast.IsGenerated(f.ast) {
				continue
			}
			files++
			fn(rel, relFile(rel, f.name), f.ast, importNames(f.ast))
		}
	}
	return files
}

// majorVersion is a module path's /vN suffix.
var majorVersion = regexp.MustCompile(`^v[0-9]+$`)

// importNames maps the name a file uses for an import to its path.
func importNames(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, s := range f.Imports {
		p := importPath(s)
		name := defaultName(p)
		if s.Name != nil {
			name = s.Name.Name
		}
		out[name] = p
	}
	return out
}

// defaultName is the name a package is used by without an import name:
// its last path element, skipping a /vN suffix.
func defaultName(path string) string {
	name := filepath.Base(path)
	if majorVersion.MatchString(name) {
		name = filepath.Base(filepath.Dir(path))
	}
	return name
}

// tally sorts findings and folds repeats into one entry with a count, so a
// file with the same break twice stays listed until both are gone.
func tally(findings []string) []string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f]++
	}
	out := make([]string, 0, len(counts))
	for f, n := range counts {
		if n > 1 {
			f = fmt.Sprintf("%s (%d times)", f, n)
		}
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

func stringValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// requireRule fails on a finding the allowlist does not name, on an entry
// with no reason or no finding, and when the rule scanned nothing.
func requireRule(t *testing.T, findings []string, files int, allowed map[string]string, hint string) {
	t.Helper()
	if files == 0 {
		t.Fatal("scanned no Go file: the rule checks nothing")
	}
	for _, p := range checkStoreNeutral(findings, allowed) {
		t.Errorf("%s\n\t%s", p, hint)
	}
}

// --- Error codes and reasons --------------------------------------------

// screaming is an enum value or an error code: SCREAMING_SNAKE_CASE.
var screaming = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// codeKeys are the fields that carry a tool error's code or reason.
var codeKeys = []string{"Code", "Reason", "ErrorCode"}

// codeLiteralFindings are the error codes and reasons spelled as a string
// literal where they are used: a Code, Reason or ErrorCode field set to a
// SCREAMING_SNAKE_CASE literal, or a Code("...") conversion. A code or
// reason is a constant in its catalog; its users name the constant.
func codeLiteralFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(_, file string, f *ast.File, _ map[string]string) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				k, ok := x.Key.(*ast.Ident)
				if !ok || !slices.Contains(codeKeys, k.Name) {
					return true
				}
				if v, ok := stringValue(x.Value); ok && screaming.MatchString(v) {
					out = append(out, fmt.Sprintf("%s: %s %q", file, k.Name, v))
				}
			case *ast.CallExpr:
				if len(x.Args) != 1 || calleeName(x.Fun) != "Code" {
					return true
				}
				if v, ok := stringValue(x.Args[0]); ok && screaming.MatchString(v) {
					out = append(out, fmt.Sprintf("%s: Code(%q)", file, v))
				}
			}
			return true
		})
	})
	return tally(out), files
}

func calleeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// codeLiteralsAllowed are today's code and reason literals.
var codeLiteralsAllowed = map[string]string{
	`internal/platform/shim/plugin_source.go: Code "INTERNAL"`: "the shim answers with its own literal; " +
		"guidance.CodeInternal is the constant",
	`internal/platform/shim/plugin_source.go: Code "INVALID_ARGUMENT"`: "the shim answers with its own literal; " +
		"guidance.CodeInvalidArgument is the constant",
	`internal/platform/shim/plugin_source.go: Reason "BAD_MANIFEST"`: "the shim spells the plugin refusal's reason; " +
		"pluginmodel.RefusedBadManifest is the constant",
	`internal/platform/mcpserver/server.go: Code "INTERNAL"`: "the server's panic answer spells the code; " +
		"guidance.CodeInternal is the constant",
	`internal/plugin/upload_error.go: Code "PLUGIN_REFUSED"`: "the upload error spells the code; " +
		"plugin.CodePluginRefused is the constant",
	`internal/app/crash.go: ErrorCode "INTERNAL"`: "the crash report spells the code; " +
		"guidance.CodeInternal is the constant",
	`internal/engine/crash.go: ErrorCode "INTERNAL"`: "the crash report spells the code; " +
		"guidance.CodeInternal is the constant",
}

func TestErrorCodesAreNamedNotSpelled(t *testing.T) {
	findings, files := codeLiteralFindings(moduleTree(t))
	requireRule(t, findings, files, codeLiteralsAllowed,
		"an error code or reason is a constant in core/guidance (or its domain's reason list); name the constant")
}

// --- Person-facing time layout ------------------------------------------

// personTimeLayout starts the layout people read deadlines in. Its one
// home is guidance.PersonTime.
const personTimeLayout = "2006-01-02 15:04"

var personTimeHome = "internal/core/guidance"

func personTimeFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(rel, file string, f *ast.File, _ map[string]string) {
		if underAny(rel, []string{personTimeHome}) {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if v, ok := n.(ast.Expr); ok {
				if s, ok := stringValue(v); ok && strings.Contains(s, personTimeLayout) {
					out = append(out, file+": layout "+strconv.Quote(personTimeLayout))
				}
			}
			return true
		})
	})
	return tally(out), files
}

var personTimeAllowed = map[string]string{
	`internal/core/setupcode/check.go: layout "2006-01-02 15:04"`:               "setupcode keeps its own timeLayout",
	`internal/setup/in/setupcli/remote.go: layout "2006-01-02 15:04" (2 times)`: "the remote setup's two messages format the expiry themselves",
	`internal/setup/setuprun.go: layout "2006-01-02 15:04"`:                     "the expired-code refusal formats the expiry itself",
	`internal/setup/engine.go: layout "2006-01-02 15:04"`:                       "UTCMinute, a copy of guidance.PersonTime",
	`internal/plugin/plugin_approvals.go: layout "2006-01-02 15:04" (2 times)`:  "the plugin approval messages format the deadline themselves",
}

func TestPersonTimesUseOneLayout(t *testing.T) {
	findings, files := personTimeFindings(moduleTree(t))
	requireRule(t, findings, files, personTimeAllowed,
		"format a time people read with guidance.PersonTime")
}

// --- Statement timeout ---------------------------------------------------

// setsStatementTimeout is SQL that sets the session's statement timeout:
// set_config('statement_timeout', ...) or a SET [LOCAL] statement. A role's
// default (ALTER ROLE ... SET) is setup's and not matched.
var setsStatementTimeout = regexp.MustCompile(`(?i)set_config\(\s*'statement_timeout'|(?m)^\s*SET\s+(LOCAL\s+|SESSION\s+)?statement_timeout\b`)

func statementTimeoutFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(_, file string, f *ast.File, _ map[string]string) {
		ast.Inspect(f, func(n ast.Node) bool {
			if v, ok := n.(ast.Expr); ok {
				if s, ok := stringValue(v); ok && setsStatementTimeout.MatchString(s) {
					out = append(out, file)
				}
			}
			return true
		})
	})
	slices.Sort(out)
	return slices.Compact(out), files
}

// statementTimeoutAllowed are the files that set the timeout beside the
// one that may. When they share one helper, this list is empty.
var statementTimeoutAllowed = map[string]string{
	"internal/platform/postgres/guard/revert.go":  "sets the revert transaction's timeout itself",
	"internal/platform/postgres/store/revert.go":  "sets the revert transaction's timeout itself",
	"internal/platform/postgres/store/reader.go":  "sets the read's timeout itself",
	"internal/platform/postgres/pgpii/fields.go":  "sets the field scan's timeout itself",
	"internal/platform/postgres/pgpii/sampler.go": "sets the sample's timeout itself",
}

// checkOneHome is checkStoreNeutral for a rule that allows one home: the
// findings the allowlist does not name may be at most one file.
func checkOneHome(findings []string, allowed map[string]string) []string {
	var out []string
	var unlisted []string
	for _, f := range findings {
		if _, ok := allowed[f]; !ok {
			unlisted = append(unlisted, f)
		}
	}
	if len(unlisted) > 1 {
		out = append(out, fmt.Sprintf("%d files set it: %s", len(unlisted), strings.Join(unlisted, ", ")))
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

func TestStatementTimeoutSetInOneFile(t *testing.T) {
	findings, files := statementTimeoutFindings(moduleTree(t))
	if files == 0 {
		t.Fatal("scanned no Go file: the rule checks nothing")
	}
	for _, p := range checkOneHome(findings, statementTimeoutAllowed) {
		t.Errorf("%s\n\tthe session's statement_timeout is set in one non-test file; call its helper", p)
	}
}

// --- Connections through pgdial -----------------------------------------

// pgdialRoots may open a Postgres connection with pgx's own constructors.
var pgdialRoots = []string{"internal/platform/postgres/pgdial", "internal/testkit"}

// directDials are pgx's constructors that skip the pooler-safe settings.
var directDials = map[string][]string{
	"github.com/jackc/pgx/v5":         {"Connect", "ParseConfig"},
	"github.com/jackc/pgx/v5/pgxpool": {"New", "ParseConfig"},
}

func directDialFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(rel, file string, f *ast.File, imports map[string]string) {
		if underAny(rel, pgdialRoots) {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if slices.Contains(directDials[imports[pkg.Name]], sel.Sel.Name) {
				out = append(out, fmt.Sprintf("%s: %s.%s", file, defaultName(imports[pkg.Name]), sel.Sel.Name))
			}
			return true
		})
	})
	return tally(out), files
}

func TestConnectionsOpenThroughPgdial(t *testing.T) {
	findings, files := directDialFindings(moduleTree(t))
	requireRule(t, findings, files, map[string]string{},
		"open a Postgres connection through internal/platform/postgres/pgdial, which keeps it pooler-safe")
}

// --- squirrel placeholders ----------------------------------------------

const squirrelPath = "github.com/Masterminds/squirrel"

// squirrelStarts begin a statement builder.
var squirrelStarts = []string{"StatementBuilder", "Select", "Insert", "Update", "Delete", "Replace"}

// squirrelDollarFindings are squirrel builders that never set
// PlaceholderFormat(sq.Dollar) in their chain: squirrel's default is "?",
// which Postgres does not read.
func squirrelDollarFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(_, file string, f *ast.File, imports map[string]string) {
		sqName := ""
		for name, p := range imports {
			if p == squirrelPath {
				sqName = name
			}
		}
		if sqName == "" {
			return
		}
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && isPkgSel(sel, sqName) && slices.Contains(squirrelStarts, sel.Sel.Name) {
				if !chainSetsDollar(sel, stack, sqName) {
					out = append(out, fmt.Sprintf("%s: %s.%s without PlaceholderFormat(%s.Dollar)", file, sqName, sel.Sel.Name, sqName))
				}
			}
			stack = append(stack, n)
			return true
		})
	})
	return tally(out), files
}

func isPkgSel(sel *ast.SelectorExpr, pkg string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// chainSetsDollar walks up the method chain that starts at start (its
// parents are stack, nearest last) and reports whether it calls
// PlaceholderFormat(<sq>.Dollar).
func chainSetsDollar(start ast.Expr, stack []ast.Node, sq string) bool {
	cur := ast.Node(start)
	for i := len(stack) - 1; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.CallExpr:
			if p.Fun != cur {
				return false
			}
		case *ast.SelectorExpr:
			if p.X != cur {
				return false
			}
			if p.Sel.Name == "PlaceholderFormat" && i > 0 {
				if call, ok := stack[i-1].(*ast.CallExpr); ok && len(call.Args) == 1 {
					if a, ok := call.Args[0].(*ast.SelectorExpr); ok && isPkgSel(a, sq) && a.Sel.Name == "Dollar" {
						return true
					}
				}
			}
		default:
			return false
		}
		cur = stack[i]
	}
	return false
}

// squirrelDollarAllowed are builders used only nested in another: squirrel
// numbers a nested builder's placeholders with the outer builder's format.
var squirrelDollarAllowed = map[string]string{
	"internal/platform/postgres/store/runs.go: sq.Select without PlaceholderFormat(sq.Dollar)": "runAggregate is " +
		"only joined into a psql builder (JoinClause), which sets the placeholders",
}

func TestSquirrelBuildersUseDollarPlaceholders(t *testing.T) {
	findings, files := squirrelDollarFindings(moduleTree(t))
	requireRule(t, findings, files, squirrelDollarAllowed,
		"start every squirrel builder from one with PlaceholderFormat(sq.Dollar), as the adapters' psql does")
}

// --- Wire spellings in Go tags ------------------------------------------

var camelCaseKey = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)

// oneofValues is a validate tag's oneof list.
var oneofValues = regexp.MustCompile(`(?:^|,)oneof=([^,]*)`)

// wireTagFindings are json keys that are not camelCase and validate
// oneof= values that are not SCREAMING_SNAKE_CASE, in struct tags.
func wireTagFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(_, file string, f *ast.File, _ map[string]string) {
		ast.Inspect(f, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			raw, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				return true
			}
			tag := reflect.StructTag(raw)
			if j, ok := tag.Lookup("json"); ok {
				name, _, _ := strings.Cut(j, ",")
				if name != "" && name != "-" && !camelCaseKey.MatchString(name) {
					out = append(out, fmt.Sprintf("%s: json key %q", file, name))
				}
			}
			for _, m := range oneofValues.FindAllStringSubmatch(tag.Get("validate"), -1) {
				for v := range strings.FieldsSeq(m[1]) {
					if !screaming.MatchString(v) {
						out = append(out, fmt.Sprintf("%s: oneof value %q", file, v))
					}
				}
			}
			return true
		})
	})
	return tally(out), files
}

// wireTagsAllowed are tags that spell another system's names.
var wireTagsAllowed = map[string]string{
	`internal/status/out/updatecheck/updatecheck.go: json key "tag_name"`: "GitHub's release API names the field",
	`internal/platform/mcpserver/server.go: json key "_meta"`:             "MCP's own request field",
}

func TestWireTagsSpellTheContract(t *testing.T) {
	findings, files := wireTagFindings(moduleTree(t))
	requireRule(t, findings, files, wireTagsAllowed,
		"json keys are camelCase and enum values SCREAMING_SNAKE_CASE (CONTRACT.md); allowlist only another system's names")
}

// --- Probes --------------------------------------------------------------

// probeTree writes files (path -> source) under a new module and parses it.
func probeTree(t *testing.T, files map[string]string) map[string]*goPkg {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module probe\n\ngo 1.24\n"
	for p, src := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pkgs, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestOneHomeRulesCatchProbes(t *testing.T) {
	pkgs := probeTree(t, map[string]string{
		"internal/core/guidance/codes.go": `package guidance
const PersonTime = "2006-01-02 15:04 UTC"
type Code string
const CodeInternal Code = "INTERNAL"
`,
		"internal/bad/bad.go": `package bad

import (
	"time"

	"github.com/jackc/pgx/v5"
	pool "github.com/jackc/pgx/v5/pgxpool"
	sq "github.com/Masterminds/squirrel"
	"probe/internal/core/guidance"
)

type ToolError struct{ Code, Reason, Message string }

type Body struct {
	RunID string ` + "`json:\"run_id\"`" + `
	State string ` + "`json:\"state\" validate:\"required,oneof=OPEN closed\"`" + `
	Fine  string ` + "`json:\"fineKey,omitempty\"`" + `
	Skip  string ` + "`json:\"-\"`" + `
}

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

func f(t time.Time) any {
	_ = ToolError{Code: "INTERNAL", Reason: "BAD_MANIFEST", Message: "a sentence"}
	_ = ToolError{Reason: "the URL has no host"}
	_ = guidance.Code("NOT_FOUND")
	_ = t.Format("2006-01-02 15:04 UTC")
	_ = "SELECT pg_catalog.set_config('statement_timeout', $1, true)"
	_, _ = pgx.Connect(nil, "")
	_, _ = pool.New(nil, "")
	_ = sq.Select("a").From("b")
	_ = psql.Select("a")
	_ = sq.Select("a").PlaceholderFormat(sq.Dollar)
	return nil
}
`,
		"internal/other/timeout.go": `package other
const q = ` + "`\nSET LOCAL statement_timeout = 5\n`" + `
const role = "ALTER ROLE x SET statement_timeout = 5"
`,
	})

	codes, _ := codeLiteralFindings(pkgs)
	want := []string{
		`internal/bad/bad.go: Code "INTERNAL"`,
		`internal/bad/bad.go: Code("NOT_FOUND")`,
		`internal/bad/bad.go: Reason "BAD_MANIFEST"`,
	}
	if !slices.Equal(codes, want) {
		t.Errorf("code literals:\n got %q\nwant %q", codes, want)
	}

	times, _ := personTimeFindings(pkgs)
	if want := []string{`internal/bad/bad.go: layout "2006-01-02 15:04"`}; !slices.Equal(times, want) {
		t.Errorf("time layouts:\n got %q\nwant %q", times, want)
	}

	timeouts, _ := statementTimeoutFindings(pkgs)
	if want := []string{"internal/bad/bad.go", "internal/other/timeout.go"}; !slices.Equal(timeouts, want) {
		t.Errorf("statement timeouts:\n got %q\nwant %q", timeouts, want)
	}
	if len(checkOneHome(timeouts, map[string]string{})) == 0 {
		t.Error("two files set the timeout and the one-home check passed")
	}
	if p := checkOneHome(timeouts, map[string]string{"internal/other/timeout.go": "probe"}); len(p) != 0 {
		t.Errorf("one unlisted file must pass: %q", p)
	}

	dials, _ := directDialFindings(pkgs)
	if want := []string{"internal/bad/bad.go: pgx.Connect", "internal/bad/bad.go: pgxpool.New"}; !slices.Equal(dials, want) {
		t.Errorf("direct dials:\n got %q\nwant %q", dials, want)
	}

	sqs, _ := squirrelDollarFindings(pkgs)
	if want := []string{"internal/bad/bad.go: sq.Select without PlaceholderFormat(sq.Dollar)"}; !slices.Equal(sqs, want) {
		t.Errorf("squirrel builders:\n got %q\nwant %q", sqs, want)
	}

	tags, _ := wireTagFindings(pkgs)
	if want := []string{`internal/bad/bad.go: json key "run_id"`, `internal/bad/bad.go: oneof value "closed"`}; !slices.Equal(tags, want) {
		t.Errorf("wire tags:\n got %q\nwant %q", tags, want)
	}

	if p := checkStoreNeutral(nil, map[string]string{"gone.go: x": "fixed"}); len(p) == 0 {
		t.Error("a stale allowlist entry passed")
	}
}
