package app

import (
	"encoding/json"
	"errors"
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

	"github.com/stretchr/testify/require"
)

// serviceLogic lists the methods on *Service that do more than forward to a
// service, with the reason each is still here. The list only shrinks: when
// the logic moves to the domain that owns the answer, the entry goes, and an
// entry whose method is gone or has become a forward fails the test.
var serviceLogic = map[string]string{
	"UnavailableSteps":     "chooses the UNAVAILABLE steps by reason, here until the steps move to their domain",
	"ApprovalLinkError":    "chooses the approval-link error and the person's message by reason, here until it moves to the approval domain",
	"openApprovalAgain":    "steps of ApprovalLinkError, move with it",
	"approvalAgainMessage": "person's message of ApprovalLinkError, moves with it",
	"setupSteps":           "the pending and expired setup steps of UnavailableSteps, move with them",
	"homeHealth":           "the home page's guard and passkey read, here until the home page's use case moves to status",
}

// serviceWiring lists the methods on *Service that build the services from
// Deps. They implement no port: building the services and handing each its
// adapters is the composition root's job.
var serviceWiring = map[string]string{
	"wire":             "builds every service and connects them",
	"agentCore":        "the agent service's part of the shared settings",
	"statusCore":       "the status service's part of the shared settings",
	"pluginCore":       "the plugin service's part of the shared settings",
	"revertCore":       "the revert service's part of the shared settings",
	"approvalCore":     "the approval service's part of the shared settings",
	"linksCore":        "the delivery service's part of the shared settings",
	"agentStoreSet":    "builds the agent's StoreSet for the store's kind",
	"approvalStoreSet": "builds the approval's StoreSet",
	"revertStoreSet":   "builds the revert's StoreSet",
}

// isForward reports whether body is a forward: empty, or one return or call
// statement, or one call whose results are all discarded (_ = f()). One if,
// switch or loop is not a forward, however short.
func isForward(body *ast.BlockStmt) bool {
	switch len(body.List) {
	case 0:
		return true
	case 1:
		switch st := body.List[0].(type) {
		case *ast.ReturnStmt, *ast.ExprStmt:
			return true
		case *ast.AssignStmt:
			for _, lhs := range st.Lhs {
				if id, ok := lhs.(*ast.Ident); !ok || id.Name != "_" {
					return false
				}
			}
			return true
		}
	}
	return false
}

// receiverName is the type name of fn's receiver, with any pointer and type
// parameters taken off, or "" for a function.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.ParenExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// serviceMethods parses every non-test Go file in dir, whatever its build
// constraints, so every platform's files are read on any machine. It returns
// the number of files read, the names of the methods on Service and those
// whose body is not a forward.
func serviceMethods(t *testing.T, dir string) (files int, methods, notForward []string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		require.NoError(t, err, path)
		files++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || receiverName(fn) != "Service" {
				continue
			}
			methods = append(methods, fn.Name.Name)
			if !isForward(fn.Body) {
				notForward = append(notForward, fn.Name.Name)
			}
		}
	}
	return files, methods, notForward
}

// serviceForwardProblems checks the scan's answer against the two lists.
func serviceForwardProblems(files int, methods, notForward []string, logic, wiring map[string]string) []string {
	var problems []string
	if files == 0 || len(methods) == 0 {
		return []string{"the scan read no file or found no method on Service: it checks nothing"}
	}
	for _, name := range notForward {
		if logic[name] == "" && wiring[name] == "" {
			problems = append(problems, "(*Service)."+name+" does more than forward: move the logic to the service that owns it and leave a one-line forward")
		}
	}
	stale := func(list map[string]string, what string) {
		for name := range list {
			if !slices.Contains(notForward, name) {
				problems = append(problems, what+" entry "+name+" matches no method on Service that does more than forward: remove it")
			}
		}
	}
	stale(logic, "serviceLogic")
	stale(wiring, "serviceWiring")
	for name := range logic {
		if wiring[name] != "" {
			problems = append(problems, name+" is in both serviceLogic and serviceWiring")
		}
	}
	slices.Sort(problems)
	return problems
}

// Where internal/app implements a port, the method is a one-line forward to
// a service: a method on *Service in a non-test file is one return or call
// statement, or is listed in serviceLogic (logic waiting to move) or
// serviceWiring (building the services) with a reason.
func TestServiceMethodsOnlyForward(t *testing.T) {
	files, methods, notForward := serviceMethods(t, ".")
	require.Empty(t, serviceForwardProblems(files, methods, notForward, serviceLogic, serviceWiring))
}

// The scan is proven on a probe package: a method with logic is reported, a
// listed name that matches nothing is reported, and an empty scan fails.
func TestServiceForwardScanCatchesLogic(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	}
	write("probe.go", `//go:build ignore

package app

type Service struct{ x interface{ F() int } }

func (s *Service) Forward() int { return s.x.F() }
func (s *Service) Call() { s.x.F() }
func (s *Service) Discard() { _ = s.x.F() }
func (s *Service) Assign() { s.x = nil }
func (s Service) TwoStatements() int {
	n := s.x.F()
	return n
}
func (s *Service) OneSwitch() int {
	switch s.x.F() {
	case 1:
		return 2
	}
	return 0
}
func (s *Service) Listed() int {
	if s.x.F() > 0 {
		return 1
	}
	return 0
}
type other struct{}
func (other) Free() int { n := 1; return n }
func Plain() int { n := 1; return n }
`)
	write("probe_test.go", `package app

func (s *Service) InATest() int { n := 1; return n }
`)

	files, methods, notForward := serviceMethods(t, dir)
	require.Equal(t, 1, files)
	require.ElementsMatch(t, []string{"Forward", "Call", "Discard", "Assign", "TwoStatements", "OneSwitch", "Listed"}, methods)
	require.ElementsMatch(t, []string{"Assign", "TwoStatements", "OneSwitch", "Listed"}, notForward)

	problems := serviceForwardProblems(files, methods, notForward,
		map[string]string{"Listed": "probe", "Gone": "probe"},
		map[string]string{"Forward": "probe"})
	require.Equal(t, []string{
		"(*Service).Assign does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).OneSwitch does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).TwoStatements does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"serviceLogic entry Gone matches no method on Service that does more than forward: remove it",
		"serviceWiring entry Forward matches no method on Service that does more than forward: remove it",
	}, problems)

	files, methods, notForward = serviceMethods(t, t.TempDir())
	require.Equal(t, []string{"the scan read no file or found no method on Service: it checks nothing"},
		serviceForwardProblems(files, methods, notForward, nil, nil))
}

// portLogic lists the methods of other app types that implement a domain
// port and do more than forward, as Type.Method, with the reason each is
// still here. The list only shrinks: an entry whose method is gone, has
// become a forward or no longer implements a port fails the test.
var portLogic = map[string]string{
	"runChecker.CheckRun":        "looks the run up in the ledger and drops the run it found",
	"agentProbe.ReinstallNotice": "reads the store's reinstalls and renders the ledger's person message",
	"pgErrors.ServerMessage":     "the setup domain's DBErrors on pgx: unwraps a Postgres server error",
	"rootConfigDir.Upsert":       "the setup domain's config writer as root: checks the directory's owner before it writes",
	"rootFiles.ReadCredential":   "the setup domain's credential files as root: reads through the checked read",
	"rootFiles.Promote":          "the setup domain's credential files as root: checks the pending file before it renames it",
	"rootFiles.ClearSetup":       "the setup domain's credential files as root: picks the owner before it clears the setup",
	"rootFiles.Close":            "the setup domain's credential files as root: closes both directories",
}

// notDomains are the directories under internal/ that are not domains.
// Every other one is a domain, and the interfaces its root package declares
// are its ports.
var notDomains = map[string]bool{"app": true, "config": true, "core": true, "lib": true, "platform": true, "testkit": true}

// listedPackage is the part of go list's answer the port scan reads.
type listedPackage struct {
	ImportPath string
	Name       string
	Dir        string
	Export     string
	GoFiles    []string
	Module     *struct{ Path string }
}

// loadApp type-checks the package in dir, as built for this machine, against
// its dependencies' export data from go list, and returns it with its files
// and the root packages of the domains it reaches.
func loadApp(t *testing.T, dir string) ([]*ast.File, *types.Package, []*types.Package) {
	t.Helper()
	cmd := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Name,Dir,Export,GoFiles,Module", ".")
	cmd.Dir = dir
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		t.Fatalf("go list: %v\n%s", err, exit.Stderr)
	}
	require.NoError(t, err)
	var pkgs []listedPackage
	for dec := json.NewDecoder(strings.NewReader(string(out))); ; {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else {
			require.NoError(t, err)
		}
		pkgs = append(pkgs, p)
	}
	require.NotEmpty(t, pkgs)
	self := pkgs[len(pkgs)-1] // go list -deps lists the named package last
	require.NotNil(t, self.Module)
	exports := map[string]string{}
	for _, p := range pkgs {
		exports[p.ImportPath] = p.Export
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(exports[path])
	})
	files := make([]*ast.File, 0, len(self.GoFiles))
	for _, name := range self.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(self.Dir, name), nil, parser.SkipObjectResolution)
		require.NoError(t, err, name)
		files = append(files, f)
	}
	pkg, err := (&types.Config{Importer: imp}).Check(self.ImportPath, fset, files, nil)
	require.NoError(t, err)
	var domains []*types.Package
	prefix := self.Module.Path + "/internal/"
	for _, p := range pkgs {
		rest, ok := strings.CutPrefix(p.ImportPath, prefix)
		if !ok || strings.Contains(rest, "/") || notDomains[rest] {
			continue
		}
		d, err := imp.Import(p.ImportPath)
		require.NoError(t, err, p.ImportPath)
		domains = append(domains, d)
	}
	return files, pkg, domains
}

// domainPorts are the non-empty, non-generic interface types the domain
// root packages declare.
func domainPorts(domains []*types.Package) []*types.Named {
	var ports []*types.Named
	for _, d := range domains {
		for _, name := range d.Scope().Names() {
			tn, ok := d.Scope().Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 {
				continue
			}
			if iface, ok := named.Underlying().(*types.Interface); ok && iface.NumMethods() > 0 {
				ports = append(ports, named)
			}
		}
	}
	return ports
}

// portMethods finds the methods that pkg's own types, other than Service
// (every method of which serviceMethods checks), declare to implement one
// of ports. It returns them as Type.Method and those whose body is not a
// forward. A method promoted from an embedded field is not pkg's own.
func portMethods(files []*ast.File, pkg *types.Package, ports []*types.Named) (methods, notForward []string) {
	decls := map[int]*ast.FuncDecl{} // by the name's token.Pos
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Body != nil {
				decls[int(fn.Name.Pos())] = fn
			}
		}
	}
	seen := map[string]bool{}
	for _, name := range pkg.Scope().Names() {
		tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() || name == "Service" {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || types.IsInterface(named) || named.TypeParams().Len() > 0 {
			continue
		}
		ptr := types.NewPointer(named)
		for _, port := range ports {
			iface := port.Underlying().(*types.Interface)
			if !types.Implements(ptr, iface) {
				continue
			}
			for m := range iface.Methods() {
				obj, _, _ := types.LookupFieldOrMethod(ptr, false, m.Pkg(), m.Name())
				fn, ok := obj.(*types.Func)
				if !ok || fn.Pkg() != pkg {
					continue
				}
				decl := decls[int(fn.Pos())]
				if decl == nil || receiverName(decl) != name {
					continue
				}
				key := name + "." + fn.Name()
				if seen[key] {
					continue
				}
				seen[key] = true
				methods = append(methods, key)
				if !isForward(decl.Body) {
					notForward = append(notForward, key)
				}
			}
		}
	}
	slices.Sort(methods)
	slices.Sort(notForward)
	return methods, notForward
}

// portForwardProblems checks the port scan's answer against list.
func portForwardProblems(methods, notForward []string, list map[string]string) []string {
	if len(methods) == 0 {
		return []string{"the port scan found no app method that implements a domain port: it checks nothing"}
	}
	var problems []string
	for _, key := range notForward {
		if list[key] == "" {
			problems = append(problems, key+" implements a domain port and does more than forward: move the logic to the service that owns it and leave a one-line forward")
		}
	}
	for key := range list {
		if !slices.Contains(notForward, key) {
			problems = append(problems, "portLogic entry "+key+" matches no port method in app that does more than forward: remove it")
		}
	}
	slices.Sort(problems)
	return problems
}

// Where internal/app implements a port with a type of its own, the methods
// that implement it are one-line forwards too: a method of an app type that
// implements an interface a domain's root package declares is one return or
// call statement, or is listed in portLogic with a reason. Files for other
// platforms are not type-checked here; CI runs the test on linux.
func TestPortMethodsOnlyForward(t *testing.T) {
	files, pkg, domains := loadApp(t, ".")
	ports := domainPorts(domains)
	require.NotEmpty(t, ports, "no domain root package declares a port: the scan checks nothing")
	methods, notForward := portMethods(files, pkg, ports)
	require.Empty(t, portForwardProblems(methods, notForward, portLogic))
}

// The port scan is proven on a probe: a probe domain declares a port and a
// probe app implements it with a forward, with logic, through an embedded
// field and on Service; only the method with logic is reported.
func TestPortForwardScanCatchesLogic(t *testing.T) {
	fset := token.NewFileSet()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(fset, "probe.go", src, parser.SkipObjectResolution)
		require.NoError(t, err)
		return f
	}
	domain, err := (&types.Config{}).Check("example.com/m/internal/dom", fset, []*ast.File{parse(`package dom

type Port interface {
	Ask() int
	Tell(int)
}

type Empty interface{}

type Other interface{ Unrelated() string }
`)}, nil)
	require.NoError(t, err)
	appFiles := []*ast.File{parse(`package app

import "example.com/m/internal/dom"

type forward struct{ p dom.Port }

func (f forward) Ask() int { return f.p.Ask() }
func (f forward) Tell(n int) { f.p.Tell(n) }

type logic struct{ p dom.Port }

func (l *logic) Ask() int {
	n := l.p.Ask()
	return n + 1
}
func (l *logic) Tell(n int) {
	if n > 0 {
		l.p.Tell(n)
	}
}
func (l *logic) notAPort() int { n := 1; return n }

type embedded struct{ dom.Port }

func (e embedded) Tell(n int) { e.Port.Tell(n) }

type Service struct{ p dom.Port }

func (s *Service) Ask() int { n := 1; return n }
func (s *Service) Tell(int) {}
`)}
	imp := importerFunc(func(path string) (*types.Package, error) {
		if path == domain.Path() {
			return domain, nil
		}
		return nil, errors.New("no package " + path)
	})
	app, err := (&types.Config{Importer: imp}).Check("example.com/m/internal/app", fset, appFiles, nil)
	require.NoError(t, err)

	ports := domainPorts([]*types.Package{domain})
	require.Len(t, ports, 2) // Empty is not a port
	methods, notForward := portMethods(appFiles, app, ports)
	require.Equal(t, []string{"embedded.Tell", "forward.Ask", "forward.Tell", "logic.Ask", "logic.Tell"}, methods)
	require.Equal(t, []string{"logic.Ask", "logic.Tell"}, notForward)
	require.Equal(t, []string{
		"logic.Tell implements a domain port and does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"portLogic entry gone.Ask matches no port method in app that does more than forward: remove it",
	}, portForwardProblems(methods, notForward, map[string]string{"logic.Ask": "probe", "gone.Ask": "probe"}))
	require.Equal(t, []string{"the port scan found no app method that implements a domain port: it checks nothing"},
		portForwardProblems(nil, nil, nil))
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
