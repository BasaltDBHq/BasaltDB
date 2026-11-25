package archtest

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The domains whose imports TestStoreNeutralDomainsLinkNoStorePackage
// follows at any depth, beside the store rules that also scan their source.
// status imports pkg/trustprofile, so it skips the one
// named edge of the driver-free rule, as plugin does.
var storeDepRules = []storeRule{
	{dir: filepath.Join("internal", "links"), allowedDeps: map[string]string{}},
	{dir: filepath.Join("internal", "status"), allowedDeps: map[string]string{}, throughTrustprofile: true},
	{dir: filepath.Join("internal", "ledger"), allowedDeps: map[string]string{}},
}

// storeAdapterRoots hold the store's own code: the Postgres adapters, setup
// and handoff (which connect to the database as the person or the agent).
// Their non-test files may name a SQLSTATE and import the pgx packages.
var storeAdapterRoots = []string{
	"internal/platform/postgres",
	"internal/setup",
	"pkg/setup",
	"internal/handoff",
}

// pgxRoots may import the pgx packages: the store adapters, the wiring and
// the test kit.
var pgxRoots = append(slices.Clone(storeAdapterRoots), "internal/app", "internal/testkit")

// sqlstateRoots may name a SQLSTATE: the store adapters and the test kit.
var sqlstateRoots = append(slices.Clone(storeAdapterRoots), "internal/testkit")

func underAny(rel string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool { return rel == r || strings.HasPrefix(rel, r+"/") })
}

// pgxImports are the Postgres driver's packages: pgx (v4 and v5, with its
// pgconn and pgtype) and the old standalone pgconn.
var pgxImports = []string{"github.com/jackc/pgx", "github.com/jackc/pgconn"}

// pgxAllowed are the files outside pgxRoots that import a pgx package, each
// with its reason. Every entry is one file and one import.
var pgxAllowed = map[string]string{
	"pkg/trustprofile/pgconn.go: import github.com/jackc/pgx/v5/pgconn": "Trust and Explain take a *pgconn.Config as part of the public API " +
		"(the same named edge the driver-free rule skips)",
	"internal/platform/cli/host.go: import github.com/jackc/pgx/v5": "the CLI core dials the database for setup and repair commands; " +
		"an inbound adapter that holds a pgx handle declares the type itself",
	"internal/platform/cli/io.go: import github.com/jackc/pgx/v5": "the CLI's querier type over the pgx handle its backend wraps " +
		"(an inbound package may not import an outbound one)",
	"internal/platform/cli/io.go: import github.com/jackc/pgx/v5/pgconn":    "the CLI's querier type returns a pgconn.CommandTag",
	"internal/platform/cli/trust.go: import github.com/jackc/pgx/v5":        "the CLI connects with the trust profile applied (cli.Connect)",
	"internal/platform/cli/trust.go: import github.com/jackc/pgx/v5/pgconn": "the trust profile is applied to a parsed *pgconn.Config",
}

// pgxFindings are the imports of a pgx package by a non-test file of a
// package outside pgxRoots, as "rel/file.go: import path".
func pgxFindings(root string) ([]string, int, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	files := 0
	for rel, pk := range pkgs {
		if underAny(rel, pgxRoots) {
			continue
		}
		for _, f := range pk.files {
			files++
			for _, s := range f.ast.Imports {
				p := importPath(s)
				if slices.ContainsFunc(pgxImports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") }) {
					out = append(out, relFile(rel, f.name)+": import "+p)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

func relFile(rel, name string) string {
	if rel == "." {
		return name
	}
	return rel + "/" + name
}

func TestNoPgxOutsideTheStoreAdapters(t *testing.T) {
	findings, files, err := pgxFindings(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("scanned no Go file: the rule checks nothing")
	}
	for _, p := range checkStoreNeutral(findings, pgxAllowed) {
		t.Errorf("%s\n\tonly internal/platform/postgres, setup, handoff, internal/app and internal/testkit import pgx; "+
			"reach the store through a port its adapter implements", p)
	}
}

// sqlstateShape is a SQLSTATE: five digits or capitals, at least one a
// digit (every Postgres code and every guard code BSnnn has one, which
// keeps words such as READY or MERGE out).
var sqlstateShape = regexp.MustCompile(`^[0-9A-Z]{5}$`)

func isSQLState(s string) bool {
	return sqlstateShape.MatchString(s) && strings.ContainsAny(s, "0123456789")
}

// sqlstateInText is a SQLSTATE named in a sentence: "(SQLSTATE 42P01)".
var sqlstateInText = regexp.MustCompile(`(?i)\bsqlstate\b\W*[0-9A-Z]{5}\b`)

// codeWord is a name that says its value is a code or a state.
var codeWord = regexp.MustCompile(`(?i)code|state`)

// sqlstateFindings are the string literals of a non-test file under root,
// outside sqlstateRoots, that use a SQLSTATE as a code: one named in a
// sentence after the word SQLSTATE, or a bare one next to a name that says
// code or state (the key it is the value of, the operand it is compared
// with, the switch it is a case of, the name it is declared or assigned to,
// the call it is an argument of, the type of the literal it is in).
func sqlstateFindings(root string) ([]string, int, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	files := 0
	for rel, pk := range pkgs {
		if underAny(rel, sqlstateRoots) {
			continue
		}
		for _, f := range pk.files {
			files++
			var stack []ast.Node
			ast.Inspect(f.ast, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						switch {
						case sqlstateInText.MatchString(v) && slices.ContainsFunc(strings.Fields(v), func(w string) bool {
							return isSQLState(strings.Trim(w, "()[]:;,.'\""))
						}):
							out = append(out, relFile(rel, f.name)+": text "+lit.Value)
						case isSQLState(v) && nextToCodeWord(stack):
							out = append(out, relFile(rel, f.name)+": code "+lit.Value)
						}
					}
				}
				stack = append(stack, n)
				return true
			})
		}
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

// nextToCodeWord reports whether a literal whose parents are stack (the
// nearest last) stands next to a name that says code or state, looking up
// to the enclosing function or declaration.
func nextToCodeWord(stack []ast.Node) bool {
	var names []string
	collect := func(nodes ...ast.Node) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			ast.Inspect(n, func(x ast.Node) bool {
				if id, ok := x.(*ast.Ident); ok {
					names = append(names, id.Name)
				}
				return true
			})
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		switch x := stack[i].(type) {
		case *ast.FuncDecl, *ast.FuncLit, *ast.GenDecl, *ast.File:
			return slices.ContainsFunc(names, codeWord.MatchString)
		case *ast.KeyValueExpr:
			collect(x.Key)
		case *ast.BinaryExpr:
			collect(x)
		case *ast.CaseClause:
			for j := i - 1; j >= 0; j-- {
				if sw, ok := stack[j].(*ast.SwitchStmt); ok {
					if sw.Tag != nil {
						collect(sw.Tag)
					}
					break
				}
			}
		case *ast.ValueSpec:
			for _, n := range x.Names {
				collect(n)
			}
		case *ast.AssignStmt:
			for _, e := range x.Lhs {
				collect(e)
			}
		case *ast.CallExpr:
			collect(x)
		case *ast.CompositeLit:
			if x.Type != nil {
				collect(x.Type)
			}
		}
	}
	return slices.ContainsFunc(names, codeWord.MatchString)
}

func TestNoSQLStateOutsideTheStoreAdapters(t *testing.T) {
	findings, files, err := sqlstateFindings(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("scanned no Go file: the rule checks nothing")
	}
	for _, f := range findings {
		t.Errorf("%s\n\ta SQLSTATE is the Postgres store's answer; its adapter (internal/platform/postgres, setup or handoff) "+
			"maps it to a typed error the rest of the code decides on", f)
	}
}

func TestStoreBoundRulesCatchViolations(t *testing.T) {
	root := fixture(t, map[string]string{
		"internal/a/a.go": `package a

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

const sqlstateUndefinedTable = "42P01"

type answer struct{ Code, Message string }

var (
	_ = answer{Code: "P0001"}
	_ = errors.New("relation missing (SQLSTATE 42P01)")
	_ = "a refused write (sqlstate: BS007)"

	_ = "READY"
	_ = "MERGE"
	_ = answer{Message: "ES256"}
	_ = "at most 20 runs and 1000 lines"
	_ = "id 123456, ref abc12345, version v0.1.0"
	_ = "SQLSTATE"
)

const SigAlg = "ES256"

func classify(err error, state string) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "XX000" {
		return "internal"
	}
	switch pg.Code {
	case "57014":
		return "cancelled"
	}
	switch state {
	case "READY":
		return state
	}
	errCode := "3F000"
	return errCode
}

var retryableCodes = map[string]bool{"40001": true, "40P01": true}

// No name next to it says code or state.
var retryable = map[string]bool{"23505": true}
`,
		"internal/a/a_test.go": `package a

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/platform/postgres/p/p.go": `package p

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/setup/s.go": `package s

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"pkg/setup/s.go": `package s

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/handoff/h.go": `package h

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/app/app.go": `package app

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/testkit/k/k.go": `package k

import _ "github.com/jackc/pgx/v5"

var code = "42P01"
`,
		"internal/platform/cli/cli.go": `package cli

import _ "github.com/jackc/pgx/v5/pgxpool"
`,
		"pkg/other/o.go": `package o

import _ "github.com/jackc/pgconn"
`,
	})

	codes, files, err := sqlstateFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	if files != 4 {
		t.Fatalf("scanned %d files for codes, want 4 (test files, the store adapters and the test kit are left out)", files)
	}
	wantCodes := []string{
		`internal/a/a.go: code "3F000"`,
		`internal/a/a.go: code "40001"`,
		`internal/a/a.go: code "40P01"`,
		`internal/a/a.go: code "42P01"`,
		`internal/a/a.go: code "57014"`,
		`internal/a/a.go: code "P0001"`,
		`internal/a/a.go: code "XX000"`,
		`internal/a/a.go: text "a refused write (sqlstate: BS007)"`,
		`internal/a/a.go: text "relation missing (SQLSTATE 42P01)"`,
		`internal/app/app.go: code "42P01"`,
	}
	if !slices.Equal(codes, wantCodes) {
		t.Errorf("code findings:\n%s\nwant:\n%s", strings.Join(codes, "\n"), strings.Join(wantCodes, "\n"))
	}

	imports, files, err := pgxFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	if files != 3 {
		t.Fatalf("scanned %d files for imports, want 3 (test files and the allowed roots are left out)", files)
	}
	wantImports := []string{
		`internal/a/a.go: import github.com/jackc/pgx/v5/pgconn`,
		`internal/platform/cli/cli.go: import github.com/jackc/pgx/v5/pgxpool`,
		`pkg/other/o.go: import github.com/jackc/pgconn`,
	}
	if !slices.Equal(imports, wantImports) {
		t.Errorf("import findings:\n%s\nwant:\n%s", strings.Join(imports, "\n"), strings.Join(wantImports, "\n"))
	}
	allowed := map[string]string{
		`internal/platform/cli/cli.go: import github.com/jackc/pgx/v5/pgxpool`: "a reason",
		`internal/platform/cli/gone.go: import github.com/jackc/pgx/v5`:        "it was removed",
	}
	wantProblems := []string{
		`allowlist entry "internal/platform/cli/gone.go: import github.com/jackc/pgx/v5" matches nothing; remove it`,
		`internal/a/a.go: import github.com/jackc/pgx/v5/pgconn`,
		`pkg/other/o.go: import github.com/jackc/pgconn`,
	}
	if got := checkStoreNeutral(imports, allowed); !slices.Equal(got, wantProblems) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantProblems, "\n"))
	}
}
