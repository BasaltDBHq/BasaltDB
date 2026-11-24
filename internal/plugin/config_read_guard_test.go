package plugin

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fileReads are the calls that open or read a file by path: the plugin
// package reads engine.json only through Ports.ReadConfig (as root, the
// engine's hardened read), so every other one must be listed here.
var fileReads = map[string]map[string]bool{
	"os":     {"ReadFile": true, "Open": true, "OpenFile": true},
	"config": {"Load": true, "LoadOpen": true, "LoadOpenRaw": true, "LoadNoFollow": true},
}

// pluginFileReads are the only places in the plugin package's own sources
// (not its tests, not its in/ and out/ adapters) that open or read a file
// by path, as file:function:package.call(path argument), with why none is
// engine.json.
var pluginFileReads = map[string]string{
	"install.go:copyFile:os.OpenFile(dst)":                                                      "creates a copy's file in the plugin root (O_EXCL)",
	"install.go:writeNew:os.OpenFile(p)":                                                        "creates a new file in the plugin root (O_EXCL)",
	"kept_entries.go:readEntries:os.OpenFile(p)":                                                "the engine-kept entries file in the state directory, no link followed",
	"plugin_feed.go:load:os.ReadFile(filepath.Join(r.cursorDir(), r.pair.agent+\".json\"))":     "a feed cursor in the state directory",
	"plugin_watch.go:step:os.ReadFile(w.ep.kept.EntriesPath())":                                 "the engine-kept entries file, for its change",
	"plugin_watch.go:stepKept:os.ReadFile(w.ep.kept.EntriesPath())":                             "the engine-kept entries file, for its change",
	"plugin_watch.go:ReadPluginServing:os.ReadFile(filepath.Join(stateDir, PluginServingFile))": "PluginServingFile in the state directory, read by the CLI",
	"plugins_service.go:osUnitSource:os.Open(path)":                                             "a service plugin's systemd or launchd unit file",
	"trust.go:readNoFollow:os.OpenFile(path)":                                                   "a copy's manifest or signature, no link followed",
	"trust.go:readOwned:os.OpenFile(path)":                                                      "a key in the trust store, no link followed, owner checked",
	"verify.go:checkFileHash:os.OpenFile(p)":                                                    "a copy's file in the plugin root, no link followed",
}

// fileReadsIn lists the calls of fileReads in f, as name:function:pkg.call.
func fileReadsIn(name string, f *ast.File) []string {
	names := map[string]string{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var pkg string
		switch path {
		case "os":
			pkg = "os"
		case "github.com/basaltdbhq/basaltdb/internal/config":
			pkg = "config"
		default:
			continue
		}
		local := pkg
		if imp.Name != nil {
			local = imp.Name.Name
		}
		names[local] = pkg
	}
	var found []string
	read := func(n ast.Node) (string, bool) {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		pkg, ok := names[id.Name]
		if !ok || !fileReads[pkg][sel.Sel.Name] {
			return "", false
		}
		return pkg + "." + sel.Sel.Name, true
	}
	for _, decl := range f.Decls {
		where := "<package>"
		if fn, ok := decl.(*ast.FuncDecl); ok {
			where = fn.Name.Name
		}
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if at, ok := read(call.Fun); ok {
					arg := ""
					if len(call.Args) > 0 {
						var b strings.Builder
						_ = printer.Fprint(&b, token.NewFileSet(), call.Args[0])
						arg = b.String()
					}
					found = append(found, name+":"+where+":"+at+"("+arg+")")
					for _, a := range call.Args {
						ast.Inspect(a, visit)
					}
					return false
				}
			}
			if at, ok := read(n); ok {
				// Not called here: a read taken as a value.
				found = append(found, name+":"+where+":"+at)
			}
			return true
		}
		ast.Inspect(decl, visit)
	}
	return found
}

// TestPluginReadsEngineConfigOnlyThroughPort: the plugin package never
// opens or reads engine.json itself; config.Load and a plain os.ReadFile
// follow a link, check no owner or mode and, at a FIFO, block. Every file
// read it makes is listed, with why, and a listed one that is gone fails.
func TestPluginReadsEngineConfigOnlyThroughPort(t *testing.T) {
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
		found = append(found, fileReadsIn(name, f)...)
	}
	require.NotEmpty(t, found, "the package's sources are scanned")
	sort.Strings(found)
	var stray []string
	for _, at := range found {
		if _, ok := pluginFileReads[at]; !ok {
			stray = append(stray, at)
		}
	}
	require.Empty(t, stray, "read engine.json through Ports.ReadConfig (the engine's read, hardened as root); list any other file read here with why")
	for at := range pluginFileReads {
		require.Contains(t, found, at, "stale entry in pluginFileReads")
	}
}

func TestFileReadGuardSeesEveryRead(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Equal(t, []string{"x.go:a:os.ReadFile(\"p\")", "x.go:b:os.Open(w.path)", "x.go:c:os.OpenFile", "x.go:d:config.Load(\"p\")", "x.go:<package>:os.ReadFile"},
		fileReadsIn("x.go", parse(`package p
import (
	"os"
	"github.com/basaltdbhq/basaltdb/internal/config"
)
func a() { os.ReadFile("p") }
func b() { os.Open(w.path) }
func c() { f := os.OpenFile; f("p", 0, 0) }
func d() { config.Load("p") }
var g = os.ReadFile
`)))
	require.Equal(t, []string{"x.go:a:os.ReadFile(\"p\")", "x.go:a:config.LoadOpenRaw(\"p\")"}, fileReadsIn("x.go", parse(`package p
import (
	stdos "os"
	cfg "github.com/basaltdbhq/basaltdb/internal/config"
)
func a() { stdos.ReadFile("p"); cfg.LoadOpenRaw("p", nil) }
`)), "a renamed import is seen")
	require.Empty(t, fileReadsIn("x.go", parse(`package p
import "os"
func a() { os.Stat("p"); os.WriteFile("p", nil, 0) }
`)))
}
