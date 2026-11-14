package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// plainConfigLoads are the only functions in this package allowed to read
// the engine config with plain config.Load, which follows links and blocks
// on a FIFO. Every other read goes through loadEngineConfig, the hardened
// read as root. Each entry is file:function, with the reason it is safe.
var plainConfigLoads = map[string]string{
	// The non-root branch: euid is not 0.
	"personfiles.go:loadEngineConfig": "only when not root",
	// No root on that platform.
	"personfiles_other.go:loadConfigAsRoot": "platform without root",
	// The engine reads its own config, after --user drops root.
	"engine.go:runEngineOn": "the engine's own config",
	// basalt mcp runs as the agent's OS user.
	"engine.go:engineDownServer": "basalt mcp, as the agent's user",
}

// No root code path reads the engine config with plain config.Load: a new
// call outside plainConfigLoads fails here, so it uses loadEngineConfig.
func TestNoRootPathUsesPlainConfigLoad(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var found []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		f, err := parser.ParseFile(fset, name, src, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Load" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "config" {
					found = append(found, name+":"+fn.Name.Name)
				}
				return true
			})
		}
	}
	sort.Strings(found)
	var stray []string
	for _, at := range found {
		if _, ok := plainConfigLoads[at]; !ok {
			stray = append(stray, at)
		}
	}
	require.Empty(t, stray, "read the engine config with loadEngineConfig (the hardened read as root), not config.Load")
	for at := range plainConfigLoads {
		require.Contains(t, found, at, "stale entry in plainConfigLoads")
	}
}
