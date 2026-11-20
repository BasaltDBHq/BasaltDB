package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const pgdialImport = "github.com/basaltdbhq/basaltdb/internal/pgdial"

// credentialReaders are the functions that read an agent's credential file:
// the config package's, and this package's own. A new reader must be added
// here, or the guard cannot see its callers. The guard works per function:
// one CheckForeignDSN call in a function marks every read in it checked.
var (
	configCredentialReaders = map[string]bool{"ReadCredential": true, "ReadCredentialAt": true, "ReadOwnCredential": true}
	localCredentialReaders  = map[string]bool{
		"readOwnedCredential": true, "readCredentialFrom": true, "readCredentialFile": true,
		"readOwnCredential": true, "readKeptCredential": true,
	}
)

// uncheckedCredentialReads are the credential reads whose function does not
// call pgdial.CheckForeignDSN, each with why root never connects with a
// string another user wrote there. Every other read must call it.
var uncheckedCredentialReads = map[string]string{
	"cmd/basalt/personfiles.go:engineConfig.credential:config.ReadCredential":           "not root; as root it is readCredentialAsRoot",
	"cmd/basalt/personfiles.go:readCredentialFlag:config.ReadCredential":                "not root; as root it is readCredentialAsRoot",
	"cmd/basalt/personfiles_other.go:readCredentialAsRoot:config.ReadCredential":        "no root on this platform",
	"cmd/basalt/keptcred_unix.go:readKeptCredential:readOwnedCredential":                "service install writes it back for the engine's user and never connects with it",
	"cmd/basalt/engine.go:keptCredentialSpec:readKeptCredential":                        "service install writes it back for the engine's user and never connects with it",
	"cmd/basalt/keptcred_unix.go:readOwnCredential:readCredentialFile":                  "only a file this process's user owns (ownedByThisUser): root's own as root",
	"cmd/basalt/keptcred_unix.go:readCredentialFile:readCredentialFrom":                 "its owner rule is its caller's, and its callers are listed here",
	"cmd/basalt/init_remote.go:pathCredFiles.read:readOwnCredential":                    "init --remote not as root",
	"internal/engine/credfiles.go:pathFiles.readCredential:config.ReadCredential":       "an engine not running as root (agentFilesFor)",
	"internal/engine/credfiles.go:pathFiles.readPending:config.ReadOwnCredential":       "an engine not running as root (agentFilesFor)",
	"internal/engine/handoff_files.go:handoffFiles.ReadSecret:config.ReadOwnCredential": "a password, not a connection string, read only on a YES, which an engine running as root never reaches (it never collects)",
}

// checkedCredentialReads are root's reads of another user's file, which call
// pgdial.CheckForeignDSN. Listed so the scan is seen to find them.
var checkedCredentialReads = []string{
	"cmd/basalt/personfiles_unix.go:readCredentialAsRoot:readOwnedCredential",
	"cmd/basalt/credfiles_unix.go:rootCredFiles.read:readCredentialFrom",
	"internal/engine/credfiles_unix.go:rootFiles.read:config.ReadCredentialAt",
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
// pgdial.CheckForeignDSN. local: f is in this package, whose own readers
// count too.
func credentialReadsIn(name string, f *ast.File, local bool) map[string]bool {
	cfg, cfgDot := importNames(f, configImport)
	pg, pgDot := importNames(f, pgdialImport)
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
					if pg[id.Name] && n.Sel.Name == "CheckForeignDSN" {
						checked = true
					}
				}
				ast.Inspect(n.X, visit)
				return false
			case *ast.Ident:
				switch {
				case cfgDot && configCredentialReaders[n.Name]:
					reads = append(reads, "config."+n.Name)
				case local && localCredentialReaders[n.Name]:
					reads = append(reads, n.Name)
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
	parse := func(rel string, local bool) {
		src, err := os.ReadFile(filepath.Join("..", "..", rel))
		require.NoError(t, err)
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, 0)
		require.NoError(t, err)
		for k, v := range credentialReadsIn(rel, f, local) {
			found[k] = v
		}
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			parse("cmd/basalt/"+name, true)
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
			if rel == "internal/engine/config" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			parse(rel, false)
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
`), true))
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredential": true}, credentialReadsIn("x.go", parse(`package main
import (
	cfg "`+configImport+`"
	pd "`+pgdialImport+`"
)
func a() { s, _ := cfg.ReadCredential("p"); pd.CheckForeignDSN(s) }
`), false))
	require.Equal(t, map[string]bool{"x.go:a:config.ReadCredentialAt": false}, credentialReadsIn("x.go", parse(`package main
import . "`+configImport+`"
func a() { ReadCredentialAt(d, "n"); readOwnedCredential("p", 0, "") }
`), false), "another package's readOwnedCredential is not this one's")
	require.Empty(t, credentialReadsIn("x.go", parse(`package main
func a() { var m reader; m.ReadCredential("p"); x.readOwnCredential("p") }
`), true))
}
