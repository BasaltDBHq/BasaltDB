package app

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

	"github.com/stretchr/testify/require"
)

const configImport = "github.com/basaltdbhq/basaltdb/internal/config"

// configLoaders are the config package's functions that read the engine
// config from a path: the loaders, and the writers that read it before they
// change it. The *At variants, which take an opened directory, are not.
var configLoaders = map[string]bool{
	"Load": true, "LoadOpen": true, "LoadOpenRaw": true, "LoadNoFollow": true,
	"UpsertAgent": true, "UpsertAgentVault": true, "UpsertedVault": true,
	"ClearSetup": true, "UpdateConfig": true, "RemoveAgents": true,
}

// portConfigLoaders are the methods of setup.EngineFiles that forward a
// config loader, with the loader each forwards: a call to one of them on
// any receiver other than a package counts as that loader, so the callers
// of the port stay in view.
var portConfigLoaders = map[string]string{
	"LoadConfig": "Load", "UpsertAgentVault": "UpsertAgentVault", "RemoveAgents": "RemoveAgents",
}

// importedNames is every name file f imports a package under.
func importedNames(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range f.Imports {
		switch {
		case imp.Name == nil:
			out[path.Base(strings.Trim(imp.Path.Value, `"`))] = true
		case imp.Name.Name != "." && imp.Name.Name != "_":
			out[imp.Name.Name] = true
		}
	}
	return out
}

// plainConfigLoads are the only places in cmd/basalt and internal/
// allowed to call a config loader directly. Every other read goes through
// cli.LoadEngineConfig (or cli.LoadEngineConfigAs, or cli.ReadEngineConfigAs
// for the plugin watch, through plugin.Ports.ReadConfig), the hardened read
// as root. Each entry is file:function:loader, the file named from the
// repository root, with the reason it is safe.
var plainConfigLoads = map[string]string{
	// The non-root branch: euid is not 0.
	"internal/platform/cli/config.go:ReadEngineConfigAs:LoadOpenRaw": "only when not root",
	// The hardened read itself: OpenTrustedFile and CheckConfigFile.
	"internal/platform/cli/config_unix.go:loadConfigAsRoot:LoadOpenRaw": "the hardened read",
	// No root on that platform.
	"internal/platform/cli/config_other.go:loadConfigAsRoot:LoadOpenRaw": "platform without root",
	// basalt mcp runs as the agent's OS user.
	"internal/status/in/statusmcp/enginedown.go:LoadEngineDown:Load": "basalt mcp, as the agent's user",
	// service install, as root, reads only pii.maxMemoryMB for the unit's
	// memory limits, refusing a link at the config; the config itself is
	// read again through openEngineFile before anything is written.
	"internal/app/engine_commands.go:runServiceAt:LoadNoFollow": "the unit's memory limit only",
	// basalt mcp reads the socket directory and the agents from the config,
	// as the agent's OS user.
	"internal/engine/in/enginecli/mcp.go:RunMCPAt:Load": "basalt mcp, as the agent's user",
	// The hand-off reads a connect-only agent's pending setup from the
	// engine config, as the engine's own user, refusing a link at it.
	"internal/handoff/out/handofffiles/setupfiles.go:PendingSetup:LoadNoFollow": "the engine's hand-off, as the engine's user",
	// The setup page's agent jobs (update, remove, repair) refuse an
	// engine that runs as root before they read the config.
	"internal/setup/local_agentjobs.go:configuredAgent:Load": "the setup page's agent jobs, after refusing an engine that runs as root",
	// Reached only after configuredAgent, which refuses an engine that
	// runs as root.
	"internal/setup/local_agentjobs.go:validateAgentJob:Load": "after configuredAgent refused an engine that runs as root",
	// runAgentJob's removal, after validateAgentJob (configuredAgent)
	// refused an engine that runs as root.
	"internal/setup/local_agentjobs.go:forget:Load": "a removal, after configuredAgent refused an engine that runs as root",
	// The setup page's reset refuses an engine that runs as root before it
	// reads the config.
	"internal/setup/local_reset.go:engineConfig:Load":                      "the setup page's reset, after refusing an engine that runs as root",
	"internal/app/setup.go:agentServiceSpec:UpsertedVault":                 "the hardened read: root opens the existing config through openEngineFile",
	"internal/handoff/out/handofffiles/pathfiles.go:ClearSetup:ClearSetup": "the engine's hand-off, as the engine's user",
	"internal/handoff/out/handofffiles/setupfiles.go:change:UpdateConfig":  "never as root: a root engine never collects an address (ErrEngineAsRoot), so the confirm step that writes the config is never reached",
	"internal/setup/local_agentjobs.go:forget:RemoveAgents":                "a removal, after configuredAgent refused an engine that runs as root",
	"internal/setup/local_run.go:writeConfig:UpsertAgentVault":             "an engine with no config writes its first engine.json; WaitsForConfig never waits as root",
	// The setup page's engine files forward each loader for the callers
	// listed above (setup.EngineFiles), which reach them by port.
	"internal/setup/out/enginefiles/enginefiles.go:LoadConfig:Load":                   "a one-line forward; its callers are listed above",
	"internal/setup/out/enginefiles/enginefiles.go:RemoveAgents:RemoveAgents":         "a one-line forward; its caller, forget, is listed above",
	"internal/setup/out/enginefiles/enginefiles.go:UpsertAgentVault:UpsertAgentVault": "a one-line forward; its caller, writeConfig, is listed above",
	"internal/setup/in/setupcli/remote.go:writeConfig:UpsertAgentVault":               "not as root: as root the upsert goes through the config directory opened without following links (configDir)",
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
	imported := importedNames(f)
	var found []string
	scan := func(where string, n ast.Node) {
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				id, isIdent := n.X.(*ast.Ident)
				if isIdent && pkgs[id.Name] && configLoaders[n.Sel.Name] {
					found = append(found, name+":"+where+":"+n.Sel.Name)
				}
				if loader, ok := portConfigLoaders[n.Sel.Name]; ok && (!isIdent || !imported[id.Name]) {
					found = append(found, name+":"+where+":"+loader)
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

// No root code path reads the engine config with a config loader directly:
// a new call outside plainConfigLoads, in the binary (cmd/basalt) or
// anywhere under internal/, this package included, fails here, so it uses
// cli.LoadEngineConfig. Every package is scanned, so code moved into a new
// package stays in view. Not scanned: internal/config, which defines the
// loaders, and _test.go files.
func TestNoRootPathUsesPlainConfigLoad(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	var found []string
	parse := func(rel string) {
		src, err := os.ReadFile(filepath.Join("..", "..", rel))
		require.NoError(t, err)
		f, err := parser.ParseFile(fset, rel, src, 0)
		require.NoError(t, err)
		found = append(found, configLoadsIn(rel, f)...)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "cmd", "basalt", "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "the binary's sources are scanned too")
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			parse("cmd/basalt/" + filepath.Base(name))
		}
	}
	var walked int
	require.NoError(t, filepath.WalkDir(filepath.Join("..", "..", "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Join("..", ".."), path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "internal/config" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			parse(rel)
			walked++
		}
		return nil
	}))
	require.NotZero(t, walked, "internal/'s sources are scanned too")
	slices.Sort(found)
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
	require.Equal(t, []string{"x.go:a:LoadNoFollow", "x.go:a:LoadOpenRaw"}, configLoadsIn("x.go", parse(`package main
import cfg "`+configImport+`"
func a() { cfg.LoadNoFollow("p"); cfg.LoadOpenRaw("p", nil) }
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
	require.Equal(t, []string{"x.go:a:Load", "x.go:b:UpsertAgentVault", "x.go:c:RemoveAgents"}, configLoadsIn("x.go", parse(`package main
import "other"
func a() { s.be.LoadConfig("p") }
func b() { f.fs.UpsertAgentVault("p", st, ag) }
func c() { files.RemoveAgents("p", nil); other.LoadConfig("p") }
`)), "a call through the engine-files port is the loader it forwards, on any receiver but a package")
}
