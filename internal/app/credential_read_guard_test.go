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

const pgdialImport = "github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"

// appImport is this package: it has no credential reader of its own.
const appImport = "github.com/basaltdbhq/basaltdb/internal/app"

// credentialReaders are the functions that read an agent's credential file:
// the config package's, and the credential file adapter's (credfiles). A
// new reader must be added here, or the guard cannot see its callers
// (TestCredentialReaderTableIsReal holds every name to a real function). The
// guard works per function: one CheckForeignDSN call in a function marks
// every read in it checked.
var (
	configCredentialReaders = map[string]bool{
		"ReadCredential": true, "ReadCredentialAt": true, "ReadCredentialAtLimit": true,
		"ReadOwnCredential": true, "ReadOwnCredentialLimit": true,
	}
	credfilesCredentialReaders = map[string]bool{
		"readOwnedCredential": true, "readCredentialFrom": true, "readCredentialFile": true,
		"readOwnCredential": true, "ReadKeptCredential": true,
	}
)

// credfilesImport is the setup domain's credential file adapter: the readers
// of basalt init --remote and basalt service install.
// portCredentialReaders are the methods of setup.EngineFiles and
// setup.ServiceHost that forward a credential reader: a call to one on any receiver other than a package
// counts as a read, so the callers of the port stay in view.
var portCredentialReaders = map[string]bool{"ReadCredentialFile": true, "ReadKeptCredential": true}

const credfilesImport = "github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"

// readerPkg is a package with credential readers of its own, the config
// package aside: a call through its import (under any name, or a
// dot-import) counts as a read in any file, recorded as name.Reader, and an
// unqualified call counts in its own folder.
type readerPkg struct {
	name    string
	folder  string
	readers map[string]bool
}

// readerPkgs are the packages with credential readers, by import path. app
// forwards credfiles' reader, which only it may reach (it imports the
// adapter): a call through app is a read too.
var readerPkgs = map[string]readerPkg{
	credfilesImport: {name: "credfiles", folder: "internal/setup/out/credfiles", readers: credfilesCredentialReaders},
}

// folderReaders is the readers an unqualified call counts as in folder.
func folderReaders(folder string) map[string]bool {
	for _, p := range readerPkgs {
		if p.folder == folder {
			return p.readers
		}
	}
	return nil
}

// uncheckedCredentialReads are the credential reads whose function does not
// call pgdial.CheckForeignDSN, each with why root never connects with a
// string another user wrote there. Every other read must call it.
var uncheckedCredentialReads = map[string]string{
	"internal/setup/out/credfiles/keptcred_unix.go:ReadKeptCredential:readOwnedCredential":     "service install writes it back for the engine's user and never connects with it",
	"internal/setup/service_install.go:ServiceInstaller.KeptCredentialSpec:ReadKeptCredential": "service install writes it back for the engine's user and never connects with it",
	// app forwards credfiles.ReadKeptCredential for setup.ServiceHost: a read
	// site of its own.
	"internal/app/setuphost.go:setupHost.ReadKeptCredential:credfiles.ReadKeptCredential":                "a one-line forward; its one caller, KeptCredentialSpec, is listed above",
	"internal/setup/out/credfiles/keptcred_unix.go:readOwnCredential:readCredentialFile":                 "only a file this process's user owns (ownedByThisUser): root's own as root",
	"internal/setup/out/credfiles/keptcred_unix.go:readCredentialFile:readCredentialFrom":                "its owner rule is its caller's, and its callers are listed here",
	"internal/setup/out/credfiles/pathfiles.go:PathCredFiles.Read:readOwnCredential":                     "init --remote not as root",
	"internal/handoff/out/handofffiles/pathfiles.go:PathFiles.ReadCredential:config.ReadCredential":      "an engine not running as root (agentFilesFor)",
	"internal/handoff/out/handofffiles/pathfiles.go:PathFiles.ReadPending:config.ReadOwnCredentialLimit": "an engine not running as root (agentFilesFor)",
	"internal/handoff/out/handofffiles/cache.go:ProbeCacheFile.Read:config.ReadOwnCredential":            "the probe cache, not a connection string; never as root (a root engine does not collect, basalt status refuses root)",
	"internal/setup/local_agentjobs.go:LocalService.credentialTarget:ReadCredentialFile":                 "the setup page's UPDATE and REMOVE: parsed for its target only, never connected with; refused as root (validateAgentJob)",
	"internal/setup/out/enginefiles/enginefiles.go:Files.ReadCredentialFile:config.ReadCredential":       "a one-line forward; its caller, Service.credentialTarget, is listed above",
	"internal/handoff/out/handofffiles/setupfiles.go:SetupFiles.ReadSecret:config.ReadOwnCredential":     "a password, not a connection string, read only on a YES, which an engine running as root never reaches (it never collects)",
}

// checkedCredentialReads are root's reads of another user's file, which call
// pgdial.CheckForeignDSN. Listed so the scan is seen to find them.
var checkedCredentialReads = []string{
	"internal/setup/out/credfiles/credfiles_unix.go:RootCredFiles.Read:readCredentialFrom",
	"internal/handoff/out/handofffiles/rootfiles_unix.go:RootFiles.read:config.ReadCredentialAt",
	"internal/handoff/out/handofffiles/rootfiles_unix.go:RootFiles.read:config.ReadCredentialAtLimit",
	"internal/app/setupbackend/setupbackend.go:Backend.ReadCredential:config.ReadCredential",
}

// importNames is the names file f imports path under, and whether it
// imports it with a dot.
func importNames(f *ast.File, path string) (map[string]bool, bool) {
	names, dot := map[string]bool{}, false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != path {
			continue
		}
		switch {
		case imp.Name == nil:
			names[filepath.Base(path)] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	return names, dot
}

// funcName is fn's name, with its receiver's type for a method.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// credentialReadsIn is every reference to a credential reader in f, as
// name:function:reader, and whether that function calls
// pgdial.CheckForeignDSN. folder is f's folder from the module root: the
// readers of the package there count unqualified too.
func credentialReadsIn(name string, f *ast.File, folder string) map[string]bool {
	cfg, cfgDot := importNames(f, configImport)
	pg, pgDot := importNames(f, pgdialImport)
	// qualified is the reader package each import name stands for; local
	// the readers an unqualified name counts as, with the prefix it is
	// recorded under ("" in its own folder).
	qualified := map[string]readerPkg{}
	local := map[string]string{}
	for r := range folderReaders(folder) {
		local[r] = ""
	}
	for path, p := range readerPkgs {
		names, dot := importNames(f, path)
		for n := range names {
			qualified[n] = p
		}
		if dot {
			for r := range p.readers {
				local[r] = p.name + "."
			}
		}
	}
	imported := importedNames(f)
	found := map[string]bool{}
	scan := func(where string, body ast.Node) {
		var reads []string
		checked := false
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if id, isIdent := n.X.(*ast.Ident); portCredentialReaders[n.Sel.Name] && (!isIdent || !imported[id.Name]) {
					reads = append(reads, n.Sel.Name)
				}
				if id, ok := n.X.(*ast.Ident); ok {
					if cfg[id.Name] && configCredentialReaders[n.Sel.Name] {
						reads = append(reads, "config."+n.Sel.Name)
					}
					if p, ok := qualified[id.Name]; ok && p.readers[n.Sel.Name] {
						reads = append(reads, p.name+"."+n.Sel.Name)
					}
					if pg[id.Name] && n.Sel.Name == "CheckForeignDSN" {
						checked = true
					}
				}
				ast.Inspect(n.X, visit)
				return false
			case *ast.Ident:
				prefix, isLocal := local[n.Name]
				switch {
				case cfgDot && configCredentialReaders[n.Name]:
					reads = append(reads, "config."+n.Name)
				case isLocal:
					reads = append(reads, prefix+n.Name)
				case pgDot && n.Name == "CheckForeignDSN":
					checked = true
				}
			}
			return true
		}
		ast.Inspect(body, visit)
		for _, r := range reads {
			found[name+":"+where+":"+r] = checked
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Body != nil {
				scan(funcName(fn), fn.Body)
			}
			continue
		}
		scan("<package>", decl)
	}
	return found
}

// Root connects with the credential it reads, and pgx reads files for the
// caller from some parameters, so every root read of a credential file
// another user owns must pass pgdial.CheckForeignDSN. Every read of a
// credential file in cmd/basalt and internal (the config package aside, which
// defines the readers) either is in a function that calls it, or is listed
// in uncheckedCredentialReads with the reason root never connects with what
// another user wrote there.
func TestRootCredentialReadsAreChecked(t *testing.T) {
	t.Parallel()
	found := map[string]bool{}
	parse := func(rel string) {
		src, err := os.ReadFile(filepath.Join("..", "..", rel))
		require.NoError(t, err)
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, 0)
		require.NoError(t, err)
		for k, v := range credentialReadsIn(rel, f, path.Dir(rel)) {
			found[k] = v
		}
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "cmd", "basalt", "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "cmd/basalt's sources are scanned too")
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			parse("cmd/basalt/" + filepath.Base(name))
		}
	}
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
		}
		return nil
	}))

	var unchecked []string
	for at, checked := range found {
		if _, listed := uncheckedCredentialReads[at]; !checked && !listed {
			unchecked = append(unchecked, at)
		}
	}
	slices.Sort(unchecked)
	require.Empty(t, unchecked, "a credential read without pgdial.CheckForeignDSN: as root, check a file another user owns, "+
		"or list it in uncheckedCredentialReads with why root never connects with it")
	for at := range uncheckedCredentialReads {
		checked, ok := found[at]
		require.True(t, ok, "stale entry in uncheckedCredentialReads: %s", at)
		require.False(t, checked, "%s calls CheckForeignDSN: drop it from uncheckedCredentialReads", at)
	}
	for _, at := range checkedCredentialReads {
		require.True(t, found[at], "%s no longer reads a credential with CheckForeignDSN", at)
	}
}

func TestCredentialReadGuardSeesEveryReader(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Equal(t, map[string]bool{
		"x.go:a:config.ReadCredential":            false,
		"x.go:t.b:config.ReadCredentialAt":        true,
		"x.go:c:readOwnedCredential":              false,
		"x.go:<package>:config.ReadOwnCredential": false,
	}, credentialReadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	"`+pgdialImport+`"
)
func a() { config.ReadCredential("p") }
func (r *t) b() { s, _, _ := config.ReadCredentialAt(d, "n"); pgdial.CheckForeignDSN(s) }
func c() { f := readOwnedCredential; f("p", 0, "") }
var g = config.ReadOwnCredential
`), "internal/setup/out/credfiles"))
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredential": true}, credentialReadsIn("x.go", parse(`package main
import (
	cfg "`+configImport+`"
	pd "`+pgdialImport+`"
)
func a() { s, _ := cfg.ReadCredential("p"); pd.CheckForeignDSN(s) }
`), "internal/x"))
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredentialAt": false}, credentialReadsIn("x.go", parse(`package main
import . "`+configImport+`"
func a() { ReadCredentialAt(d, "n"); readOwnedCredential("p", 0, "") }
`), "internal/x"), "another package's readOwnedCredential is not this one's")
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredential": false, "x.go:b:config.ReadCredential": false}, credentialReadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	"`+appImport+`"
)
func a() { s, _ := config.ReadCredential("p"); app.CheckForeignDSN(s) }
func b() { s, _ := config.ReadCredential("p"); CheckForeignDSN(s) }
`), "internal/x"), "only pgdial's CheckForeignDSN checks a read: not app's, not an unqualified one")
	require.Empty(t, credentialReadsIn("x.go", parse(`package main
func a() { var m reader; m.ReadCredential("p"); x.readOwnCredential("p") }
`), "internal/setup/out/credfiles"), "a method or another package's field is not a reader")
	require.Equal(t, map[string]bool{"x.go:t.a:ReadCredentialFile": false, "x.go:b:ReadCredentialFile": true}, credentialReadsIn("x.go", parse(`package main
import (
	"other"
	"`+pgdialImport+`"
)
func (s *t) a() { s.be.ReadCredentialFile("p"); other.ReadCredentialFile("p") }
func b() { d, _ := files.ReadCredentialFile("p"); pgdial.CheckForeignDSN(d) }
`), "internal/x"), "a call through the engine-files port is a read, on any receiver but a package")
	require.Equal(t, map[string]bool{"x.go:t.c:ReadKeptCredential": false}, credentialReadsIn("x.go", parse(`package setup
func (s t) c() { s.Host.ReadKeptCredential("p", "u") }
`), "internal/setup"), "a call through the service install's host is a read")
}

// The guard follows credfiles' readers: qualified from any package, under
// an alias or a dot-import, unqualified inside credfiles' own folder, and
// not another package's function of the same name.
func TestCredentialReadGuardSeesCredfilesReaders(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Equal(t, map[string]bool{
		"x.go:a:credfiles.ReadKeptCredential":         false,
		"x.go:b:credfiles.ReadKeptCredential":         true,
		"x.go:<package>:credfiles.ReadKeptCredential": false,
	}, credentialReadsIn("x.go", parse(`package handoff
import (
	"`+credfilesImport+`"
	"`+pgdialImport+`"
)
func a() { credfiles.ReadKeptCredential(h, "p", "u") }
func b() { s, _ := credfiles.ReadKeptCredential(h, "p", "u"); pgdial.CheckForeignDSN(s) }
var g = credfiles.ReadKeptCredential
`), "internal/handoff"))
	require.Equal(t, map[string]bool{"x.go:a:credfiles.ReadKeptCredential": false}, credentialReadsIn("x.go", parse(`package handoff
import sc "`+credfilesImport+`"
func a() { sc.ReadKeptCredential(h, "p", "u") }
`), "internal/handoff"), "an alias is still credfiles")
	require.Equal(t, map[string]bool{"x.go:a:credfiles.ReadKeptCredential": false}, credentialReadsIn("x.go", parse(`package handoff
import . "`+credfilesImport+`"
func a() { ReadKeptCredential(h, "p", "u") }
`), "internal/handoff"), "a dot-import is still credfiles")
	require.Equal(t, map[string]bool{
		"x.go:a:readCredentialFrom":   false,
		"x.go:r.b:readCredentialFrom": true,
	}, credentialReadsIn("x.go", parse(`package credfiles
import "`+pgdialImport+`"
func a() { readCredentialFrom(f, nil) }
func (r *r) b() { s, _, _ := readCredentialFrom(f, nil); pgdial.CheckForeignDSN(s) }
`), "internal/setup/out/credfiles"), "credfiles' own readers count unqualified in its folder")
	require.Empty(t, credentialReadsIn("x.go", parse(`package handoff
func a() { readCredentialFrom(f, nil); ReadKeptCredential(h, "p", "u") }
`), "internal/handoff"), "another package's readCredentialFrom is not credfiles'")
	require.Empty(t, credentialReadsIn("x.go", parse(`package handoff
import "example.com/other/credfiles"
func a() { credfiles.ReadKeptCredential(h, "p", "u") }
`), "internal/handoff"), "another package named credfiles is not this one")
	require.Empty(t, credentialReadsIn("x.go", parse(`package main
import "`+appImport+`"
func a() { app.ReadOwnCredential("p") }
`), "cmd/basalt"), "app is no reader package")
}

// The reader table names real code: each package's folder holds Go files of
// that package, and each reader is a function declared there. A reader that
// moves or is renamed fails here instead of leaving the guard blind to its
// callers.
func TestCredentialReaderTableIsReal(t *testing.T) {
	t.Parallel()
	const module = "github.com/basaltdbhq/basaltdb/"
	for path, p := range readerPkgs {
		require.Equal(t, module+p.folder, path, "the folder of %s", path)
		files, err := filepath.Glob(filepath.Join("..", "..", p.folder, "*.go"))
		require.NoError(t, err)
		funcs := map[string]bool{}
		sources := 0
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			require.NoError(t, err)
			require.Equal(t, p.name, f.Name.Name, "%s is package %s", name, p.name)
			sources++
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
					funcs[fn.Name.Name] = true
				}
			}
		}
		require.NotZero(t, sources, "%s has Go files to scan", p.folder)
		for r := range p.readers {
			require.True(t, funcs[r], "%s is a function in %s", r, p.folder)
		}
	}
	// cmd/basalt has no readers of its own (they live in credfiles): a
	// reader-named function here would be called unqualified, unseen.
	files, err := filepath.Glob(filepath.Join("..", "..", "cmd", "basalt", "*.go"))
	require.NoError(t, err)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			for _, p := range readerPkgs {
				require.False(t, p.readers[fn.Name.Name], "cmd/basalt/%s declares %s, a reader name: read credentials through credfiles (app's forwarder)", filepath.Base(name), fn.Name.Name)
			}
		}
	}
}
