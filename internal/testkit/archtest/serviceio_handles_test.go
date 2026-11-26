package archtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The service-I/O check above bans I/O by package and function, and lets a
// service hold an *os.File or *os.Root. This half is type-aware: it lists
// what a service does with such a handle once it has one. A method call on
// the handle (Read, Write, OpenFile, Mkdir, Stat, Close, ...) is I/O, and so
// is handing it to a parameter of interface type (io.Copy, io.ReadAll,
// bufio.NewReader, a port that takes an io.Reader). Name only returns the
// name the handle was opened with and is not listed.

// handleGOOS are the systems the engine ships on. Each domain root package
// is type-checked once per system and the findings are joined, so the answer
// is the same on every machine that runs the test.
var handleGOOS = []string{"linux", "darwin"}

const handleIOBaseline = "serviceio_handles_baseline.txt"

type handleScan struct {
	lines    []string // counted findings, sorted
	packages int      // domain root packages type-checked, over all systems
	handles  int      // expressions of handle type seen in them
}

// handleIO type-checks every package in a domain root (the service layer)
// under root and lists, by declaration, each use of an *os.File or *os.Root
// that does I/O.
func handleIO(root string) (handleScan, error) {
	var scan handleScan
	pkgs, err := load(root)
	if err != nil {
		return scan, err
	}
	var paths []string
	for rel := range pkgs {
		if layerOf(rel) == lService {
			paths = append(paths, modulePath+"/"+rel)
		}
	}
	if len(paths) == 0 {
		return scan, nil
	}
	slices.Sort(paths)
	seen := map[string]bool{}
	for _, goos := range handleGOOS {
		lines, n, h, err := handleIOFor(root, goos, paths)
		if err != nil {
			return scan, fmt.Errorf("GOOS=%s: %w", goos, err)
		}
		for _, l := range lines {
			seen[l] = true
		}
		scan.packages += n
		scan.handles += h
	}
	for l := range seen {
		scan.lines = append(scan.lines, l)
	}
	slices.Sort(scan.lines)
	return scan, nil
}

type listedPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	Error      *struct{ Err string }
}

// handleIOFor type-checks paths for one GOOS: the packages they import come
// from the export data go list builds, the packages themselves from source.
func handleIOFor(root, goos string, paths []string) (lines []string, packages, handles int, err error) {
	args := append([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Dir,GoFiles,CgoFiles,Export,Error"}, paths...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, 0, 0, fmt.Errorf("go list: %w\n%s", err, exit.Stderr)
		}
		return nil, 0, 0, err
	}
	var listed []listedPkg
	for dec := json.NewDecoder(strings.NewReader(string(out))); ; {
		var p listedPkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, 0, 0, err
		}
		listed = append(listed, p)
	}
	exports := map[string]string{}
	for _, p := range listed {
		exports[p.ImportPath] = p.Export
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(exports[path])
	})
	var found []string
	for _, p := range listed {
		if !slices.Contains(paths, p.ImportPath) {
			continue
		}
		if len(p.GoFiles) == 0 && len(p.CgoFiles) == 0 {
			continue // no file builds on this system
		}
		if p.Error != nil {
			return nil, 0, 0, fmt.Errorf("%s: %s", p.ImportPath, p.Error.Err)
		}
		if len(p.CgoFiles) > 0 {
			return nil, 0, 0, fmt.Errorf("%s: cgo files are not checked: %v", p.ImportPath, p.CgoFiles)
		}
		rel := strings.TrimPrefix(p.ImportPath, modulePath+"/")
		files := make([]*ast.File, 0, len(p.GoFiles))
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, 0, 0, err
			}
			files = append(files, f)
		}
		info := &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		if _, err := (&types.Config{Importer: imp}).Check(p.ImportPath, fset, files, info); err != nil {
			return nil, 0, 0, fmt.Errorf("type-check %s: %w", p.ImportPath, err)
		}
		packages++
		for i, f := range files {
			for _, d := range f.Decls {
				handles += handleUses(info, d, func(n ast.Node, what string) {
					found = append(found, rel+": "+p.GoFiles[i]+": "+declName(d, n)+": "+what)
				})
			}
		}
	}
	return counted(found), packages, handles, nil
}

// handleUses reports each handle I/O in d to report and returns how many
// expressions of handle type it saw.
func handleUses(info *types.Info, d ast.Decl, report func(ast.Node, string)) (handles int) {
	ast.Inspect(d, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && isHandle(info.TypeOf(x)) {
			handles++
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			// Keyed on the method's own receiver, so a method promoted from
			// an embedded handle, a method value and a method expression
			// are all seen.
			if s := info.Selections[x]; s != nil {
				if fn, ok := s.Obj().(*types.Func); ok && handleMethod(fn) {
					report(x, "("+types.TypeString(fn.Type().(*types.Signature).Recv().Type(), pkgName)+")."+fn.Name())
				}
			}
		case *ast.CallExpr:
			if tv, ok := info.Types[x.Fun]; ok && tv.IsType() {
				return true // a conversion
			}
			sig, ok := info.TypeOf(x.Fun).Underlying().(*types.Signature)
			if !ok {
				return true
			}
			for i, arg := range x.Args {
				at := info.TypeOf(arg)
				if !isHandle(at) {
					continue
				}
				if pt := paramType(sig, i, x.Ellipsis.IsValid()); pt != nil && types.IsInterface(pt) {
					report(arg, "passes "+types.TypeString(at, pkgName)+" to "+handleCallee(info, x.Fun))
				}
			}
		}
		return true
	})
	return handles
}

func pkgName(p *types.Package) string { return p.Name() }

// isHandle reports whether t is os.File or os.Root, or a pointer to one.
func isHandle(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok {
		return false
	}
	o := n.Obj()
	return o.Pkg() != nil && o.Pkg().Path() == "os" && (o.Name() == "File" || o.Name() == "Root")
}

// handleMethod reports whether fn is a method of os.File or os.Root that
// does I/O: every one but Name.
func handleMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	return isHandle(sig.Recv().Type()) && fn.Name() != "Name"
}

// paramType is the type the i-th argument is assigned to.
func paramType(sig *types.Signature, i int, spread bool) types.Type {
	ps := sig.Params()
	n := ps.Len()
	if n == 0 {
		return nil
	}
	if sig.Variadic() && i >= n-1 {
		last := ps.At(n - 1).Type()
		if spread {
			return last
		}
		if s, ok := last.Underlying().(*types.Slice); ok {
			return s.Elem()
		}
		return nil
	}
	if i >= n {
		return nil
	}
	return ps.At(i).Type()
}

// handleCallee names the function or method fun calls: io.Copy,
// (*bufio.Writer).ReadFrom, a module package without its module path, or
// "a func value" when it is not a declared function.
func handleCallee(info *types.Info, fun ast.Expr) string {
	fun = ast.Unparen(fun)
	var id *ast.Ident
	switch f := fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.IndexExpr:
		return handleCallee(info, f.X)
	case *ast.IndexListExpr:
		return handleCallee(info, f.X)
	}
	if id != nil {
		if fn, ok := info.Uses[id].(*types.Func); ok {
			return strings.ReplaceAll(fn.FullName(), modulePath+"/", "")
		}
	}
	return "a func value"
}

func TestServicesDoNoHandleIO(t *testing.T) {
	root := moduleRoot(t)
	scan, err := handleIO(root)
	if err != nil {
		t.Fatal(err)
	}
	if scan.packages == 0 || scan.handles == 0 {
		t.Fatalf("the handle scan type-checked %d domain root packages and saw %d handles: it checks nothing", scan.packages, scan.handles)
	}
	file := filepath.Join(root, "internal", "testkit", "archtest", handleIOBaseline)
	var base []string
	if _, err := os.Stat(file); err == nil {
		base = readLines(t, file)
	}
	if *update {
		// -update only removes lines: a new finding is fixed, never listed.
		base = shrinkBaseline(base, scan.lines)
		if len(base) == 0 {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(file, []byte(strings.Join(base, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range handleBaselineProblems(base, scan.lines) {
		t.Error(p)
	}
}

// handleBaselineProblems compares the findings with the baseline: a finding
// the baseline does not list is new I/O, a baseline line that is no longer
// found is stale. A count that drops changes the line, so the old line is
// stale and the new one is new: edit the count down by hand.
func handleBaselineProblems(base, got []string) []string {
	var out []string
	for _, l := range got {
		if !slices.Contains(base, l) {
			out = append(out, l+"\n\tnew I/O on a file or root handle in a service; move it into the port's out/ adapter (do not add it to "+handleIOBaseline+")")
		}
	}
	for _, l := range base {
		if !slices.Contains(got, l) {
			out = append(out, l+"\n\tno longer true; remove it from "+handleIOBaseline+" (or lower its count)")
		}
	}
	return out
}

func TestHandleBaselineProblems(t *testing.T) {
	base := []string{"a", "b (2 times)"}
	got := []string{"a", "b", "new"}
	want := []string{
		"b\n\tnew I/O on a file or root handle in a service; move it into the port's out/ adapter (do not add it to " + handleIOBaseline + ")",
		"new\n\tnew I/O on a file or root handle in a service; move it into the port's out/ adapter (do not add it to " + handleIOBaseline + ")",
		"b (2 times)\n\tno longer true; remove it from " + handleIOBaseline + " (or lower its count)",
	}
	if p := handleBaselineProblems(base, got); !slices.Equal(p, want) {
		t.Errorf("problems:\n got %q\nwant %q", p, want)
	}
	if p := handleBaselineProblems(got, got); len(p) != 0 {
		t.Errorf("a matching baseline has problems: %q", p)
	}
}

const handleProbeMod = "module " + modulePath + "\n\ngo 1.26\n"

func TestHandleIOCatchesViolations(t *testing.T) {
	m := modulePath + "/"
	root := fixture(t, map[string]string{
		"go.mod": handleProbeMod,
		"internal/lib/files/f.go": "package files\n\nimport \"os\"\n\n" +
			"func Open(name string) (*os.File, error) { return os.Open(name) }\n",
		"internal/ledger/ports.go": "package ledger\n\nimport \"os\"\n\n" +
			"type Files interface {\n\tOpen(name string) (*os.File, error)\n\tOpenRoot(dir string) (*os.Root, error)\n}\n\n" +
			"type wrapped struct{ *os.File }\n",
		"internal/ledger/h.go": "package ledger\n\nimport (\n\t\"bufio\"\n\t\"io\"\n\t\"os\"\n\n\t\"" + m + "internal/lib/files\"\n)\n\n" +
			"func Copy(fs Files, w io.Writer) error {\n\tf, err := fs.Open(\"x\")\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer f.Close()\n\t_ = f.Name()\n\t_, err = io.Copy(w, f)\n\t_, _ = io.ReadAll(f)\n\t_, _ = io.ReadAll(f)\n\treturn err\n}\n\n" +
			"func Root(fs Files) {\n\tr, _ := fs.OpenRoot(\"d\")\n\t_ = r.Mkdir(\"a\", 0o700)\n\t_ = r.Name()\n}\n\n" +
			"func Embedded(w wrapped) { _ = w.Sync() }\n\n" +
			"func Value(f *os.File) func([]byte) (int, error) { return f.Write }\n\n" +
			"var chmod = (*os.File).Chmod\n\n" +
			"func Buffered(f *os.File) *bufio.Reader { return bufio.NewReader(f) }\n\n" +
			"func Module() { f, _ := files.Open(\"x\"); _, _ = f.Stat() }\n\n" +
			"func Keep(f *os.File) *os.File { return keep(f) }\n\nfunc keep(f *os.File) *os.File { return f }\n",
		"internal/ledger/l_linux.go":  "//go:build linux\n\npackage ledger\n\nimport \"os\"\n\nfunc OnLinux(f *os.File) { _ = f.Sync() }\n",
		"internal/ledger/l_darwin.go": "//go:build darwin\n\npackage ledger\n\nimport \"os\"\n\nfunc OnDarwin(f *os.File) { _ = f.Sync() }\n",
		"internal/ledger/out/disk/d.go": "package disk\n\nimport \"os\"\n\n" +
			"func Write(f *os.File) { _, _ = f.Write(nil) }\n",
	})
	scan, err := handleIO(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/ledger: h.go: Buffered: passes *os.File to bufio.NewReader",
		"internal/ledger: h.go: Copy: (*os.File).Close",
		"internal/ledger: h.go: Copy: passes *os.File to io.Copy",
		"internal/ledger: h.go: Copy: passes *os.File to io.ReadAll (2 times)",
		"internal/ledger: h.go: Embedded: (*os.File).Sync",
		"internal/ledger: h.go: Module: (*os.File).Stat",
		"internal/ledger: h.go: Root: (*os.Root).Mkdir",
		"internal/ledger: h.go: Value: (*os.File).Write",
		"internal/ledger: h.go: chmod: (*os.File).Chmod",
		"internal/ledger: l_darwin.go: OnDarwin: (*os.File).Sync",
		"internal/ledger: l_linux.go: OnLinux: (*os.File).Sync",
	}
	if !slices.Equal(scan.lines, want) {
		t.Errorf("handleIO:\n got %q\nwant %q", scan.lines, want)
	}
	if scan.packages != 2 {
		t.Errorf("type-checked %d packages, want internal/ledger once per system (2)", scan.packages)
	}
}

func TestHandleIOPassesWithoutHandleIO(t *testing.T) {
	root := fixture(t, map[string]string{
		"go.mod": handleProbeMod,
		"internal/ledger/ports.go": "package ledger\n\nimport \"os\"\n\n" +
			"type Files interface{ Open(name string) (*os.File, error) }\n\n" +
			"func Named(fs Files) string {\n\tf, err := fs.Open(\"x\")\n\tif err != nil {\n\t\treturn \"\"\n\t}\n\treturn f.Name()\n}\n",
	})
	scan, err := handleIO(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.lines) != 0 || scan.packages == 0 || scan.handles == 0 {
		t.Errorf("handleIO = %q over %d packages and %d handles, want no finding over a checked package", scan.lines, scan.packages, scan.handles)
	}
}

func TestHandleIOScansNothingWithoutDomainRoots(t *testing.T) {
	root := fixture(t, map[string]string{
		"go.mod":                     handleProbeMod,
		"internal/lib/files/f.go":    "package files\n\nimport \"os\"\n\nfunc Sync(f *os.File) { _ = f.Sync() }\n",
		"internal/ledger/out/d/d.go": "package d\n\nimport \"os\"\n\nfunc Sync(f *os.File) { _ = f.Sync() }\n",
	})
	scan, err := handleIO(root)
	if err != nil {
		t.Fatal(err)
	}
	if scan.packages != 0 || scan.handles != 0 || len(scan.lines) != 0 {
		t.Errorf("handleIO outside domain roots = %+v, want an empty scan (which TestServicesDoNoHandleIO fails)", scan)
	}
}
