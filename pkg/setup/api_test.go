package setup_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// moduleRoot is the engine module's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// No exported name of the package mentions a type from an internal
// package: another module could not name it.
func TestExportedAPIHasNoInternalType(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	checked := 0
	for _, entry := range entries {
		if name := entry.Name(); strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			file, err := parser.ParseFile(fset, name, nil, 0)
			require.NoError(t, err)
			internal := internalImports(t, file)
			for _, decl := range file.Decls {
				for _, expr := range exportedTypeExprs(decl) {
					checked++
					ast.Inspect(expr, func(n ast.Node) bool {
						sel, ok := n.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						if id, ok := sel.X.(*ast.Ident); ok && internal[id.Name] {
							t.Errorf("%s: exported API uses %s.%s from an internal package", fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
						}
						return true
					})
				}
			}
		}
	}
	require.Positive(t, checked)
}

// internalImports are the names file imports internal packages under.
func internalImports(t *testing.T, file *ast.File) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		require.NoError(t, err)
		if !strings.Contains(path, "/internal/") {
			continue
		}
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = true
	}
	return out
}

// exportedTypeExprs are the type expressions of decl that other packages
// see: exported functions' and methods' signatures, exported types (only
// their exported fields and methods), and exported constants' and
// variables' types and values.
func exportedTypeExprs(decl ast.Decl) []ast.Expr {
	var out []ast.Expr
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Name.IsExported() && (d.Recv == nil || exportedReceiver(d.Recv)) {
			out = append(out, d.Type)
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					out = append(out, exportedParts(s.Type)...)
				}
			case *ast.ValueSpec:
				for i, n := range s.Names {
					if !n.IsExported() {
						continue
					}
					if s.Type != nil {
						out = append(out, s.Type)
					}
					// A constant's value is a basic type: only a variable's
					// can carry an internal one.
					if d.Tok == token.VAR && i < len(s.Values) {
						out = append(out, s.Values[i])
					}
				}
			}
		}
	}
	return out
}

// exportedParts is a type definition without its unexported struct fields.
func exportedParts(typ ast.Expr) []ast.Expr {
	st, ok := typ.(*ast.StructType)
	if !ok {
		return []ast.Expr{typ}
	}
	var out []ast.Expr
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 || f.Names[0].IsExported() {
			out = append(out, f.Type)
		}
	}
	return out
}

func exportedReceiver(recv *ast.FieldList) bool {
	typ := recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	return ok && id.IsExported()
}

// importer uses every step of the package from another module.
const importer = `package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

func main() {
	ctx := context.Background()
	req := setup.Request{Code: "basalt-setup.1.x.y", Now: time.Now()}
	var desc setup.Description
	desc, err := setup.Describe(req)
	var refused *setup.Error
	fmt.Println(desc.Fingerprint, err, refused)
	var conn *pgx.Conn
	if conn == nil {
		return
	}
	var checked setup.Checked
	checked, err = setup.Check(ctx, conn, req)
	var pkReq setup.PasskeyRequest
	pkReq, err = setup.NewPasskeyRequest(rand.Reader, "label", "db")
	var res setup.Result
	res, err = setup.Run(ctx, conn, req, setup.RunInput{
		Answers: setup.Answers{AllRows: []string{checked.Questions.RowSecurity[0].Table}},
		Approve: func(p setup.Plan) error { fmt.Println(p.SQL); return nil },
		Passkey: func(context.Context) (setup.Passkey, error) { return pkReq.Verify("basalt-passkey.1.x") },
	})
	fmt.Println(res.Ran, err)
}
`

// The package builds from a module outside the engine's.
func TestBuildsFromAnotherModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module")
	}
	t.Parallel()
	root, err := filepath.Abs(moduleRoot(t))
	require.NoError(t, err)
	dir := t.TempDir()
	goMod := "module example.com/setupimporter\n\ngo 1.26.0\n\nrequire github.com/basaltdbhq/basaltdb v0.0.0\n\n" +
		"replace github.com/basaltdbhq/basaltdb => " + root + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600))
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(importer), 0o600))

	cmd := exec.Command("go", "build", "-mod=mod", "-o", filepath.Join(dir, "importer"), ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
}
