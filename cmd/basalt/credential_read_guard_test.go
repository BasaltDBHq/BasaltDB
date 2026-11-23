package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const pgdialImport = "github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"

// appImport is where cmd reaches pgdial.CheckForeignDSN from: app re-exports it.
const appImport = "github.com/basaltdbhq/basaltdb/internal/app"

// credentialReaders are the functions that read an agent's credential file:
// the config package's, and this package's own. A new reader must be added
// here, or the guard cannot see its callers. The guard works per function:
// one CheckForeignDSN call in a function marks every read in it checked.
var (
	configCredentialReaders = map[string]bool{
		"ReadCredential": true, "ReadCredentialAt": true, "ReadCredentialAtLimit": true,
		"ReadOwnCredential": true, "ReadOwnCredentialLimit": true,
	}
	localCredentialReaders = map[string]bool{
		"readOwnedCredential": true, "readCredentialFrom": true, "readCredentialFile": true,
		"readOwnCredential": true, "readKeptCredential": true,
	}
	credfilesCredentialReaders = map[string]bool{
		"readOwnedCredential": true, "readCredentialFrom": true, "readCredentialFile": true,
		"readOwnCredential": true, "readKeptCredential": true,
		"ReadOwnedCredential": true, "ReadCredentialFrom": true, "ReadCredentialFile": true,
		"ReadOwnCredential": true, "ReadKeptCredential": true,
	}
)

// credfilesImport is the setup domain's credential file adapter: the readers
// of basalt init --remote and basalt service install.
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
// forwards credfiles' readers to cmd, which may not import an adapter: a
// call through app is a read too.
var readerPkgs = map[string]readerPkg{
	"github.com/basaltdbhq/basaltdb/cmd/basalt": {name: "main", folder: "cmd/basalt", readers: localCredentialReaders},
	credfilesImport: {name: "credfiles", folder: "internal/setup/out/credfiles", readers: credfilesCredentialReaders},
	appImport:       {name: "app", folder: "internal/app", readers: map[string]bool{"ReadKeptCredential": true}},
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
	"cmd/basalt/keptcred_unix.go:readKeptCredential:readOwnedCredential":                "service install writes it back for the engine's user and never connects with it",
	"cmd/basalt/engine.go:keptCredentialSpec:readKeptCredential":                        "service install writes it back for the engine's user and never connects with it",
	"cmd/basalt/keptcred_unix.go:readOwnCredential:readCredentialFile":                  "only a file this process's user owns (ownedByThisUser): root's own as root",
	"cmd/basalt/keptcred_unix.go:readCredentialFile:readCredentialFrom":                 "its owner rule is its caller's, and its callers are listed here",
	"cmd/basalt/init_remote.go:pathCredFiles.read:readOwnCredential":                    "init --remote not as root",
	"internal/handoff/pathfiles.go:PathFiles.ReadCredential:config.ReadCredential":      "an engine not running as root (agentFilesFor)",
	"internal/handoff/pathfiles.go:PathFiles.ReadPending:config.ReadOwnCredentialLimit": "an engine not running as root (agentFilesFor)",
	"internal/handoff/cache.go:FileCache.Load:config.ReadOwnCredential":                 "the probe cache, not a connection string; never as root (a root engine does not collect, basalt status refuses root)",
	"internal/setup/in/localsetup/agentjobs.go:credentialTarget:config.ReadCredential":  "the setup page's UPDATE and REMOVE: parsed for its target only, never connected with; refused as root (validateAgentJob)",
	"internal/app/handoff_files.go:handoffFiles.ReadSecret:config.ReadOwnCredential":    "a password, not a connection string, read only on a YES, which an engine running as root never reaches (it never collects)",
}

// checkedCredentialReads are root's reads of another user's file, which call
// pgdial.CheckForeignDSN. Listed so the scan is seen to find them.
var checkedCredentialReads = []string{
	"cmd/basalt/credfiles_unix.go:rootCredFiles.read:readCredentialFrom",
	"internal/app/credfiles_unix.go:rootFiles.read:config.ReadCredentialAt",
	"internal/app/credfiles_unix.go:rootFiles.read:config.ReadCredentialAtLimit",
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
	appNames, _ := importNames(f, appImport)
	maps.Copy(pg, appNames)
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
	found := map[string]bool{}
	scan := func(where string, body ast.Node) {
		var reads []string
		checked := false
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
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
// credential file in cmd and internal (the config package aside, which
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
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			parse("cmd/basalt/" + name)
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
	sort.Strings(unchecked)
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
`), "cmd/basalt"))
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
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredentialAt": true}, credentialReadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	"`+appImport+`"
)
func a() { s, _, _ := config.ReadCredentialAt(d, "n"); app.CheckForeignDSN(s) }
`), "internal/x"), "app re-exports pgdial.CheckForeignDSN: a call through it checks the read")
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredential": true}, credentialReadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	engine "`+appImport+`"
)
func a() { s, _ := config.ReadCredential("p"); engine.CheckForeignDSN(s) }
`), "internal/x"))
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredential": false}, credentialReadsIn("x.go", parse(`package main
import (
	"`+configImport+`"
	"example.com/other/app"
)
func a() { s, _ := config.ReadCredential("p"); app.CheckForeignDSN(s) }
`), "internal/x"), "another package's app.CheckForeignDSN is not the engine's")
	require.Empty(t, credentialReadsIn("x.go", parse(`package main
func a() { var m reader; m.ReadCredential("p"); x.readOwnCredential("p") }
`), "cmd/basalt"))
}

// The guard follows credfiles' readers: qualified from any package, under
// an alias or a dot-import, unqualified inside credfiles' own folder, and
// through app's forwarder; not another package's function of the same name.
func TestCredentialReadGuardSeesCredfilesReaders(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Equal(t, map[string]bool{
		"x.go:a:credfiles.ReadKeptCredential":        false,
		"x.go:b:credfiles.ReadOwnCredential":         true,
		"x.go:<package>:credfiles.ReadOwnCredential": false,
	}, credentialReadsIn("x.go", parse(`package handoff
import (
	"`+credfilesImport+`"
	"`+pgdialImport+`"
)
func a() { credfiles.ReadKeptCredential(h, "p", "u") }
func b() { s, _, _ := credfiles.ReadOwnCredential("p"); pgdial.CheckForeignDSN(s) }
var g = credfiles.ReadOwnCredential
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
	require.Equal(t, map[string]bool{"x.go:a:app.ReadKeptCredential": false}, credentialReadsIn("x.go", parse(`package main
import "`+appImport+`"
func a() { app.ReadKeptCredential(h, "p", "u") }
`), "cmd/basalt"), "app forwards credfiles' reader to cmd: a call through it is a read")
	require.Empty(t, credentialReadsIn("x.go", parse(`package main
import "`+appImport+`"
func a() { app.ReadOwnCredential("p") }
`), "cmd/basalt"), "app forwards only ReadKeptCredential")
}
