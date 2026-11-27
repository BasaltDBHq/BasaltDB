package archtest

import (
	"fmt"
	"go/ast"
	"slices"
	"strings"
	"testing"
)

// pgstatementPkg is the Postgres statement check: it parses an agent
// statement with libpg_query. Only the Postgres adapter calls it.
const pgstatementPkg = "internal/platform/postgres/pgstatement"

// postgresRoot holds the Postgres adapter, the only code that parses
// Postgres SQL.
const postgresRoot = "internal/platform/postgres"

// pgstatementFindings are, over the non-test files under root:
//   - an import of the statement check or of the Postgres parser by a
//     package outside postgresRoot;
//   - in the statement check itself, an import core may not make (the
//     driver among them) other than the parser, a dot-import, or a call of
//     time.Now, time.Since or time.Until: it stays pure and testable without
//     a database.
func pgstatementFindings(root string) ([]string, int, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	files := 0
	for rel, pk := range pkgs {
		inside := underAny(rel, []string{postgresRoot})
		check := underAny(rel, []string{pgstatementPkg})
		for _, f := range pk.files {
			files++
			for _, s := range f.ast.Imports {
				p := importPath(s)
				switch {
				case !inside && (p == modulePath+"/"+pgstatementPkg || strings.HasPrefix(p, modulePath+"/"+pgstatementPkg+"/")):
					out = append(out, relFile(rel, f.name)+": import "+p+" (only the Postgres adapter checks Postgres statements)")
				case !inside && pgParser(p):
					out = append(out, relFile(rel, f.name)+": import "+p+" (only the Postgres adapter parses Postgres SQL)")
				case check && s.Name != nil && s.Name.Name == ".":
					out = append(out, relFile(rel, f.name)+": dot-import "+p+" (the statement check stays pure)")
				case check && bannedImport(p) && !pgParser(p):
					out = append(out, relFile(rel, f.name)+": import "+p+" (the statement check stays pure)")
				}
			}
			if check {
				out = append(out, clockCalls(relFile(rel, f.name), f.ast)...)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

// clockCalls are the uses of time.Now, time.Since and time.Until in f.
func clockCalls(name string, f *ast.File) []string {
	var out []string
	names := localNames(f)
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] == "time" && in([]string{"Now", "Since", "Until"}, sel.Sel.Name) {
			out = append(out, fmt.Sprintf("%s: calls time.%s (the statement check stays pure)", name, sel.Sel.Name))
		}
		return true
	})
	return out
}

func TestPgStatementStaysInThePostgresAdapter(t *testing.T) {
	findings, files, err := pgstatementFindings(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("scanned no Go file: the rule checks nothing")
	}
	for _, f := range findings {
		t.Errorf("%s\n\tthe Postgres statement check and parser belong to internal/platform/postgres; "+
			"another store's statements go through its own agent.Language", f)
	}
}

func TestPgStatementRuleCatchesViolations(t *testing.T) {
	m := modulePath + "/"
	root := fixture(t, map[string]string{
		"go.mod": "module " + modulePath + "\n",
		"internal/platform/postgres/pgstatement/c.go": `package pgstatement

import (
	"os"
	"time"
	. "strings"

	_ "github.com/jackc/pgx/v5"
	_ "github.com/pganalyze/pg_query_go/v6"
	_ "github.com/wasilibs/go-pgquery"
)

var _ = os.Getenv
var _ = time.Now
var _ = time.Since
var _ = time.Duration(0)
var _ = ToLower
`,
		"internal/platform/postgres/pgstatement/c_test.go": `package pgstatement

import "time"

var _ = time.Now
`,
		"internal/platform/postgres/store/s.go": "package store\n\n" + imp(m+"internal/platform/postgres/pgstatement", "github.com/pganalyze/pg_query_go/v6", "time") + "\nvar _ = time.Now\n",
		"internal/app/a.go":                     "package app\n\n" + imp(m+"internal/platform/postgres/pgstatement"),
		"internal/app/a_test.go":                "package app\n\n" + imp(m+"internal/platform/postgres/pgstatement"),
		"internal/agent/out/x/x.go":             "package x\n\n" + imp("github.com/wasilibs/go-pgquery"),
		"internal/testkit/k/k.go":               "package k\n\n" + imp("github.com/pganalyze/pg_query_go/v6", m+"internal/platform/postgres/pgstatement/inner"),
		"internal/platform/postgresx/p.go":      "package postgresx\n\n" + imp(m+"internal/platform/postgres/pgstatement"),
		"internal/core/c/c.go":                  "package c\n\n" + imp("github.com/wasilibs/go-pgqueryx"),
	})
	got, files, err := pgstatementFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	if files != 7 {
		t.Fatalf("scanned %d files, want 7 (test files are left out)", files)
	}
	want := []string{
		"internal/agent/out/x/x.go: import github.com/wasilibs/go-pgquery (only the Postgres adapter parses Postgres SQL)",
		"internal/app/a.go: import " + m + "internal/platform/postgres/pgstatement (only the Postgres adapter checks Postgres statements)",
		"internal/platform/postgres/pgstatement/c.go: calls time.Now (the statement check stays pure)",
		"internal/platform/postgres/pgstatement/c.go: calls time.Since (the statement check stays pure)",
		"internal/platform/postgres/pgstatement/c.go: dot-import strings (the statement check stays pure)",
		"internal/platform/postgres/pgstatement/c.go: import github.com/jackc/pgx/v5 (the statement check stays pure)",
		"internal/platform/postgres/pgstatement/c.go: import os (the statement check stays pure)",
		"internal/platform/postgresx/p.go: import " + m + "internal/platform/postgres/pgstatement (only the Postgres adapter checks Postgres statements)",
		"internal/testkit/k/k.go: import " + m + "internal/platform/postgres/pgstatement/inner (only the Postgres adapter checks Postgres statements)",
		"internal/testkit/k/k.go: import github.com/pganalyze/pg_query_go/v6 (only the Postgres adapter parses Postgres SQL)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
