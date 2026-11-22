package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// trustChecks are the owner, trust and credential checks cli.go hands to
// cmd. A package variable could be reassigned at run time (by a test, or by
// any code in the binary) and skip the check, so each must be a function.
var trustChecks = []string{
	"CheckForeignDSN", "CertificateNotVerified", "WithCertificateHint", "CurrentTrustProfileSet",
	"OSLookupUID", "OSOpenTrustedDir", "OSOpenTrustedFile",
}

// cliValues are cli.go's package variables, each by its value: values, never
// functions. A variable not listed here fails the test, so a function value
// cannot come back unseen.
var cliValues = map[string]any{
	"ErrOSDialogCancelled": ErrOSDialogCancelled,
	"ErrOSNoDialog":        ErrOSNoDialog,
}

// No package variable in cli.go holds a function, and the trust checks are
// declared functions.
func TestTrustChecksAreFunctions(t *testing.T) {
	t.Parallel()
	f, err := parser.ParseFile(token.NewFileSet(), "cli.go", nil, 0)
	require.NoError(t, err)
	funcs, vars := map[string]bool{}, map[string]bool{}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				funcs[d.Name.Name] = true
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				for _, n := range spec.(*ast.ValueSpec).Names {
					vars[n.Name] = true
				}
			}
		}
	}
	for name := range vars {
		v, listed := cliValues[name]
		require.True(t, listed, "%s is a package variable in cli.go: make it a function, or list a plain value in cliValues", name)
		require.NotEqual(t, reflect.Func, reflect.ValueOf(v).Kind(), "%s holds a function: declare it as one", name)
	}
	for _, name := range trustChecks {
		require.False(t, vars[name], "%s is a package variable in cli.go: make it a function", name)
		require.True(t, funcs[name], "%s is not a function in cli.go", name)
	}
}
