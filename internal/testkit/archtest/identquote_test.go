package archtest

import (
	"fmt"
	"go/ast"
	"slices"
	"testing"
)

// The SQL the engine builds quotes every identifier with one function,
// internal/lib/sqlident.Quote. This rule finds any other quoter: a call
// that doubles double quotes (strings.ReplaceAll or strings.Replace from `"`
// to `""`, or a strings.NewReplacer pair that does it) and any use of
// pgx.Identifier, whose Sanitize method quotes the same way.

const pgxPkg = "github.com/jackc/pgx/v5"

// identQuoteFindings lists, per non-test file and enclosing function, each
// quote-doubling call and each use of pgx.Identifier.
func identQuoteFindings(pkgs map[string]*goPkg) ([]string, int) {
	var out []string
	files := eachFile(pkgs, func(_, file string, f *ast.File, imports map[string]string) {
		for _, d := range f.Decls {
			name := "_"
			if fd, ok := d.(*ast.FuncDecl); ok {
				name = fd.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if doublesQuotes(x, imports) {
						out = append(out, fmt.Sprintf("%s: %s: doubles quotes", file, name))
					}
				case *ast.SelectorExpr:
					if pkg, ok := x.X.(*ast.Ident); ok && imports[pkg.Name] == pgxPkg && x.Sel.Name == "Identifier" {
						out = append(out, fmt.Sprintf("%s: %s: pgx.Identifier", file, name))
					}
				}
				return true
			})
		}
	})
	return tally(out), files
}

// doublesQuotes reports whether call is strings.ReplaceAll(s, `"`, `""`),
// strings.Replace(s, `"`, `""`, n) or strings.NewReplacer with a `"`, `""`
// pair, however the literals are spelled.
func doublesQuotes(call *ast.CallExpr, imports map[string]string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || imports[pkg.Name] != "strings" {
		return false
	}
	isPair := func(from, to ast.Expr) bool {
		a, okA := stringValue(from)
		b, okB := stringValue(to)
		return okA && okB && a == `"` && b == `""`
	}
	switch sel.Sel.Name {
	case "ReplaceAll", "Replace":
		return len(call.Args) >= 3 && isPair(call.Args[1], call.Args[2])
	case "NewReplacer":
		for i := 0; i+1 < len(call.Args); i += 2 {
			if isPair(call.Args[i], call.Args[i+1]) {
				return true
			}
		}
	}
	return false
}

// identQuoteAllowed are the quoters the rule keeps.
var identQuoteAllowed = map[string]string{
	"internal/lib/sqlident/sqlident.go: Quote: doubles quotes": "the one always-quote function",
	"internal/agent/out/sqllang/names.go: quoteIdent: doubles quotes": "the display quoter: quotes a name only " +
		"where Postgres's quote_ident would, for the names an agent reads",
}

func TestOneIdentifierQuoter(t *testing.T) {
	findings, files := identQuoteFindings(moduleTree(t))
	requireRule(t, findings, files, identQuoteAllowed,
		"quote SQL identifiers with internal/lib/sqlident.Quote")
}

// TestOneIdentifierQuoterProbe runs the rule on a copy of the quoter in
// another package, written the ways a copy could spell it.
func TestOneIdentifierQuoterProbe(t *testing.T) {
	m := modulePath + "/"
	root := fixture(t, map[string]string{
		"go.mod": "module " + modulePath + "\n",
		"internal/lib/sqlident/sqlident.go": "package sqlident\n\nimport \"strings\"\n\n" +
			"func Quote(s string) string { return `\"` + strings.ReplaceAll(s, `\"`, `\"\"`) + `\"` }\n",
		"internal/agent/out/sqllang/names.go": "package sqllang\n\nimport \"strings\"\n\n" +
			"func quoteIdent(s string) string { return `\"` + strings.ReplaceAll(s, `\"`, `\"\"`) + `\"` }\n",
		"internal/ledger/copy.go": "package ledger\n\nimport str \"strings\"\n\n" +
			"func quote(s string) string { return \"\\\"\" + str.Replace(s, \"\\\"\", \"\\\"\\\"\", -1) + \"\\\"\" }\n\n" +
			"var r = str.NewReplacer(\"\\x00\", \"\", `\"`, `\"\"`)\n",
		"internal/ledger/pgx.go": "package ledger\n\nimport (\n\tdriver \"github.com/jackc/pgx/v5\"\n\t\"" + m +
			"internal/lib/sqlident\"\n)\n\nfunc role(r string) string {\n\tid := driver.Identifier{r}\n\treturn id.Sanitize()\n}\n\n" +
			"var _ = sqlident.Quote\n",
		"internal/ledger/clean.go": "package ledger\n\nimport \"strings\"\n\n" +
			"var _ = strings.ReplaceAll(\"a\", `\"`, `\\\"`)\n",
		"internal/ledger/copy_test.go": "package ledger\n\nimport \"strings\"\n\n" +
			"var _ = strings.ReplaceAll(\"a\", `\"`, `\"\"`)\n",
	})
	pkgs, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := identQuoteFindings(pkgs)
	want := []string{
		"internal/ledger/copy.go: _: doubles quotes",
		"internal/ledger/copy.go: quote: doubles quotes",
		"internal/ledger/pgx.go: role: pgx.Identifier",
	}
	got := checkStoreNeutral(findings, identQuoteAllowed)
	if !slices.Equal(got, want) {
		t.Errorf("findings outside the allowlist:\n got %q\nwant %q", got, want)
	}
}
