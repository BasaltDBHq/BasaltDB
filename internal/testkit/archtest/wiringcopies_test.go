package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// copyFuncs are the names a test gave its own copy of what the engine wires.
var copyFuncs = []string{"testErrors", "testErrorMap", "testManager"}

// copiedValues are the production values that mark a copy when a composite
// literal sets them: the agent's error map over the Postgres adapters'
// errors, and the host's service manager. They are matched by import path,
// whatever name the file imports the package under.
var copiedValues = []struct{ key, pkg, name string }{
	{"InvalidParams", modulePath + "/internal/platform/postgres/ledger", "ErrInvalidParams"},
	{"StartCommand", modulePath + "/internal/platform/osservice", "StartCommand"},
}

// wiringCopies returns, for the Go files under root's internal, cmd and pkg,
// one "<file>: <finding>" line per copy of the agent's error map
// (pgerrors.Map) or of the host's service manager (osservice.Manager)
// outside those two homes. A test calls them instead, so it never runs on
// a copy production no longer uses.
func wiringCopies(root string) ([]string, error) {
	homes := map[string]bool{
		"internal/platform/postgres/pgerrors/pgerrors.go": true,
		"internal/platform/osservice/manager.go":          true,
	}
	var out []string
	for _, top := range []string{"internal", "cmd", "pkg"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(file string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(file, ".go") {
				return err
			}
			rel, _ := filepath.Rel(root, file)
			rel = filepath.ToSlash(rel)
			if homes[rel] || strings.HasPrefix(rel, "internal/testkit/archtest/") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			for _, l := range copiesIn(f) {
				out = append(out, rel+": "+l)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// copiesIn returns the copies f declares or builds.
func copiesIn(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && slices.Contains(copyFuncs, fd.Name.Name) {
			out = append(out, "func "+fd.Name.Name+"()")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		sel, ok2 := kv.Value.(*ast.SelectorExpr)
		if !ok || !ok2 {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		for _, c := range copiedValues {
			if key.Name == c.key && sel.Sel.Name == c.name && x.Name == localName(f, c.pkg) {
				out = append(out, c.key+": "+path.Base(c.pkg)+"."+c.name)
			}
		}
		return true
	})
	return out
}

func TestNoCopyOfTheWiredErrorsOrServiceManager(t *testing.T) {
	got, err := wiringCopies(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		t.Errorf("%s\n\tuse pgerrors.Map() or osservice.Manager(), the copies the engine wires", l)
	}
}

func TestWiringCopiesCatchesViolations(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ledgerImp := "import \"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger\"\n\n"
	write("internal/x/h_test.go", "package x\n\n"+ledgerImp+"func testErrors() guidance.ErrorMap {\n\treturn guidance.ErrorMap{InvalidParams: ledger.ErrInvalidParams}\n}\n")
	write("internal/y/m_test.go", "package y\n\nimport \"github.com/basaltdbhq/basaltdb/internal/platform/osservice\"\n\nvar m = guidance.ServiceManager{StartCommand: osservice.StartCommand}\n")
	write("internal/platform/postgres/pgerrors/pgerrors.go", "package pgerrors\n\n"+ledgerImp+"var m = guidance.ErrorMap{InvalidParams: ledger.ErrInvalidParams}\n")
	write("internal/z/fake_test.go", "package z\n\nvar m = guidance.ErrorMap{InvalidParams: errFake}\n")
	write("internal/w/alias_test.go", "package w\n\nimport pgledger \"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger\"\n\nvar m = guidance.ErrorMap{InvalidParams: pgledger.ErrInvalidParams}\n")
	write("internal/v/other_test.go", "package v\n\nimport ledger \"example.com/other/ledger\"\n\nvar m = guidance.ErrorMap{InvalidParams: ledger.ErrInvalidParams}\n")
	got, err := wiringCopies(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/w/alias_test.go: InvalidParams: ledger.ErrInvalidParams",
		"internal/x/h_test.go: func testErrors()",
		"internal/x/h_test.go: InvalidParams: ledger.ErrInvalidParams",
		"internal/y/m_test.go: StartCommand: osservice.StartCommand",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("wiringCopies = %q, want %q", got, want)
	}
}
