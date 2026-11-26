package plugin

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fileReads are the calls that open or read a file by path: the plugin
// package reads engine.json only through Ports.ReadConfig (as root, the
// engine's hardened read), so every other one must be listed here. A
// method call reads too when its name is in methodReads, whatever value it
// is called on: the Files port (named "files", whatever holds it) or a
// handle it returned, such as an *os.Root.
var fileReads = map[string]map[string]bool{
	"os":     {"ReadFile": true, "Open": true, "OpenFile": true},
	"config": {"Load": true, "LoadOpen": true, "LoadOpenRaw": true, "LoadNoFollow": true},
}

// methodReads are the method names that open or read a file by path:
// readCursor is the feed's Ports.ReadFeedCursor. A plugin method named Open
// is caught too and listed with why it reads no file.
var methodReads = map[string]bool{"ReadFile": true, "Open": true, "OpenFile": true, "OpenRoot": true, "readCursor": true}

// receiverName names the value a read method is called on: "files" for the
// Files port (an identifier or a field named files or Files), else the
// expression as written.
func receiverName(x ast.Expr) string {
	switch x := x.(type) {
	case *ast.Ident:
		if x.Name == "files" || x.Name == "Files" {
			return "files"
		}
	case *ast.SelectorExpr:
		if x.Sel.Name == "files" || x.Sel.Name == "Files" {
			return "files"
		}
	}
	var b strings.Builder
	_ = printer.Fprint(&b, token.NewFileSet(), x)
	return b.String()
}

// pluginFileReads are the only places in the plugin package's own sources
// (not its tests, not its in/ and out/ adapters) that open or read a file
// by path, as file:function:package.call(path argument), with why none is
// engine.json.
var pluginFileReads = map[string]string{
	"install.go:Stage:files.OpenRoot(src)":                                                  "the plugin source directory the person named, opened as a root",
	"install.go:copyFile:srcRoot.OpenFile(filepath.FromSlash(rel))":                         "a listed file of the source, inside its root, no link followed",
	"install.go:readSource:srcRoot.OpenFile(name)":                                          "the source's manifest or signature, inside its root, no link followed",
	"install.go:copyFile:files.OpenFile(dst)":                                               "creates a copy's file in the plugin root (O_EXCL)",
	"install.go:writeNew:files.OpenFile(p)":                                                 "creates a new file in the plugin root (O_EXCL)",
	"kept_entries.go:Manifest:files.OpenRoot(t.Dir)":                                        "an upload's directory in the state directory, opened as a root",
	"kept_entries.go:Manifest:root.OpenFile(ManifestFile)":                                  "an upload's manifest, inside the upload's root, no link followed",
	"kept_entries.go:readEntries:files.OpenFile(p)":                                         "the engine-kept entries file in the state directory, no link followed",
	"kept_upload.go:MarkExecutables:files.OpenRoot(t.Dir)":                                  "an upload's directory in the state directory, opened as a root",
	"kept_upload.go:writePart:root.OpenFile(name)":                                          "writes a part of an upload, inside the upload's root, no link followed",
	"kept_upload.go:writePart:files.OpenRoot(filepath.Join(s.uploadsDir(), u.id.String()))": "an upload's directory in the state directory, opened as a root",
	"feed.go:load:r.f.readCursor(r.cursorDir())":                                            "a feed cursor in the state directory (Ports.ReadFeedCursor)",
	"requests.go:OpenPlugin:k.Open(ctx)":                                                    "PLUGIN_OPEN on the engine-kept plugins, not a file read",
	"watch.go:step:files.ReadFile(w.ep.kept.EntriesPath())":                                 "the engine-kept entries file, for its change",
	"watch.go:stepKept:files.ReadFile(w.ep.kept.EntriesPath())":                             "the engine-kept entries file, for its change",
	"plugins_service.go:osUnitSource:files.OpenFile(path)":                                  "a service plugin's systemd or launchd unit file",
	"trust.go:readNoFollow:files.OpenFile(path)":                                            "a copy's manifest or signature, no link followed",
	"trust.go:readOwned:files.OpenFile(path)":                                               "a key in the trust store, no link followed, owner checked",
	"verify.go:checkFileHash:files.OpenFile(p)":                                             "a copy's file in the plugin root, no link followed",
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
		if methodReads[sel.Sel.Name] {
			if id, ok := sel.X.(*ast.Ident); !ok || names[id.Name] == "" {
				return receiverName(sel.X) + "." + sel.Sel.Name, true
			}
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
	slices.Sort(found)
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
	require.Equal(t, []string{"x.go:a:files.ReadFile(\"p\")", "x.go:b:files.OpenFile(path)", "x.go:c:files.OpenRoot(dir)", "x.go:d:root.OpenFile(name)", "x.go:e:fsys.ReadFile(p)", "x.go:f:r.f.readCursor(dir)"},
		fileReadsIn("x.go", parse(`package p
func a(files Files) { files.ReadFile("p"); files.Lstat("p") }
func b() { s.files.OpenFile(path, 0, 0) }
func c() { ep.o.Ports.Files.OpenRoot(dir) }
func d() { root.OpenFile(name, 0, 0) }
func e(fsys Files) { fsys.ReadFile(p) }
func f() { r.f.readCursor(dir, name) }
`)), "a read through the Files port, or a handle, under any name, is seen")
}
