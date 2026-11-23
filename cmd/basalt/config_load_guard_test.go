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

const configImport = "github.com/basaltdbhq/basaltdb/internal/config"

// configLoaders are the config package's functions that read the engine
// config from a path.
var configLoaders = map[string]bool{"Load": true, "LoadOpen": true, "LoadNoFollow": true}

// plainConfigLoads are the only places in this package and the CLI shell
// (internal/platform/cli) allowed to call a config loader directly. Every
// other read goes through cli.LoadEngineConfig (or cli.LoadEngineConfigAs),
// the hardened read as root. Each entry is file:function:loader, with the
// reason it is safe.
var plainConfigLoads = map[string]string{
	// The non-root branch: euid is not 0.
	shellDir + "config.go:LoadEngineConfigAs:Load": "only when not root",
	// The hardened read itself: OpenTrustedFile and CheckConfigFile.
	shellDir + "config_unix.go:loadConfigAsRoot:LoadOpen": "the hardened read",
	// No root on that platform.
	shellDir + "config_other.go:loadConfigAsRoot:Load": "platform without root",
	// basalt mcp runs as the agent's OS user.
	"engine.go:engineDown:Load": "basalt mcp, as the agent's user",
	// service install, as root, reads only pii.maxMemoryMB for the unit's
	// memory limits, refusing a link at the config; the config itself is
	// read again through openEngineFile before anything is written.
	"engine.go:runServiceAt:LoadNoFollow": "the unit's memory limit only",
	// basalt mcp reads the socket directory and the agents from the config,
	// as the agent's OS user.
	engineCLIDir + "mcp.go:RunMCPAt:Load": "basalt mcp, as the agent's user",
}

// configLoadsIn lists the config loaders f refers to, as
// file:function:loader (function is "<package>" outside a function), through
// the config package's import name, an alias, or a dot-import.
func configLoadsIn(name string, f *ast.File) []string {
	// Every name the package is imported under: a file may import it
	// more than once.
	pkgs, dot := map[string]bool{}, false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != configImport {
			continue
		}
		switch {
		case imp.Name == nil:
			pkgs["config"] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			pkgs[imp.Name.Name] = true
		}
	}
	if len(pkgs) == 0 && !dot {
		return nil
	}
	var found []string
	scan := func(where string, n ast.Node) {
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok && pkgs[id.Name] && configLoaders[n.Sel.Name] {
					found = append(found, name+":"+where+":"+n.Sel.Name)
				}
				// The selected name is a field or method, never the
				// dot-imported function: look only at what it selects from.
				ast.Inspect(n.X, visit)
				return false
			case *ast.Ident:
				if dot && configLoaders[n.Name] {
					found = append(found, name+":"+where+":"+n.Name)
				}
			}
			return true
		}
		ast.Inspect(n, visit)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Body != nil {
				scan(fn.Name.Name, fn.Body)
			}
			continue
		}
		scan("<package>", decl)
	}
	return found
}

// shellDir is the CLI shell's source folder, from this package, as the
// entries in plainConfigLoads name it.
const shellDir = "../../internal/platform/cli/"

// engineCLIDir is the engine's CLI controllers' source folder, from this
// package, as the entries in plainConfigLoads name it.
const engineCLIDir = "../../internal/engine/in/enginecli/"

// engineDir is the engine's use cases' source folder, from this package:
// the supervisor's config read (SuperviseConfig) passes through it.
const engineDir = "../../internal/engine/"

// No root code path reads the engine config with a config loader directly:
// a new call outside plainConfigLoads, in this package, the CLI shell, the
// engine's use cases or its CLI controllers, fails here, so it uses
// cli.LoadEngineConfig.
func TestNoRootPathUsesPlainConfigLoad(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for dir, what := range map[string]string{
		shellDir:     "the CLI shell's sources",
		engineDir:    "the engine's use cases",
		engineCLIDir: "the engine's CLI controllers",
	} {
		more, err := filepath.Glob(dir + "*.go")
		require.NoError(t, err)
		require.NotEmpty(t, more, what+" are scanned too")
		files = append(files, more...)
	}
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
		found = append(found, configLoadsIn(name, f)...)
	}
	sort.Strings(found)
	var stray []string
	for _, at := range found {
		if _, ok := plainConfigLoads[at]; !ok {
			stray = append(stray, at)
		}
	}
	require.Empty(t, stray, "read the engine config with cli.LoadEngineConfig (the hardened read as root), not a config loader")
	for at := range plainConfigLoads {
		require.Contains(t, found, at, "stale entry in plainConfigLoads")
	}
}

// The guard sees every loader, through the plain import, an alias and a
// dot-import, in a function or at package level, and is not fooled by a
// method or field of the same name.
func TestConfigLoadGuardSeesEveryLoader(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Equal(t, []string{"x.go:a:Load", "x.go:b:LoadOpen", "x.go:c:LoadNoFollow", "x.go:<package>:Load"},
		configLoadsIn("x.go", parse(`package main
import "`+configImport+`"
func a() { config.Load("p") }
func b() { config.LoadOpen("p", nil) }
func c() { f := config.LoadNoFollow; f("p") }
var g = config.Load
`)))
	require.Equal(t, []string{"x.go:a:LoadNoFollow"}, configLoadsIn("x.go", parse(`package main
import cfg "`+configImport+`"
func a() { cfg.LoadNoFollow("p") }
`)))
	require.Equal(t, []string{"x.go:a:LoadOpen", "x.go:b:Load"}, configLoadsIn("x.go", parse(`package main
import . "`+configImport+`"
func a() { LoadOpen("p", nil) }
func b() { var m sync.Map; m.Load("k"); Load("p") }
`)))
	require.Equal(t, []string{"x.go:a:Load", "x.go:a:LoadOpen"}, configLoadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	other "`+configImport+`"
)
func a() { config.Load("p"); other.LoadOpen("p", nil) }
`)), "a package imported under two names is seen under both")
	require.Empty(t, configLoadsIn("x.go", parse(`package main
import "sync"
func a() { var m sync.Map; m.Load("k") }
`)))
}
