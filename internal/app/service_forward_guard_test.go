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
var serviceLogic = map[string]string{}

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
// switch or loop is not a forward, however short, and neither is a call of a
// function literal (return func() { ... }()) or a call that passes a function
// literal of more than one statement (return s.x.Run(func() error { ...; ... })).
// A function literal of one statement passed as an argument is allowed.
func isForward(body *ast.BlockStmt) bool {
	switch len(body.List) {
	case 0:
		return true
	case 1:
		switch st := body.List[0].(type) {
		case *ast.ReturnStmt, *ast.ExprStmt:
		case *ast.AssignStmt:
			for _, lhs := range st.Lhs {
				if id, ok := lhs.(*ast.Ident); !ok || id.Name != "_" {
					return false
				}
			}
		default:
			return false
		}
		for _, call := range outerCalls(body.List[0]) {
			if _, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
				return false
			}
			for _, arg := range call.Args {
				if lit, ok := ast.Unparen(arg).(*ast.FuncLit); ok && len(lit.Body.List) > 1 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// outerCalls are the calls a forward's one statement makes at its top: the
// results of a return, the expression of a call statement, the right side
// of an assignment. Calls in their arguments are not among them.
func outerCalls(st ast.Stmt) []*ast.CallExpr {
	var exprs []ast.Expr
	switch st := st.(type) {
	case *ast.ReturnStmt:
		exprs = st.Results
	case *ast.ExprStmt:
		exprs = []ast.Expr{st.X}
	case *ast.AssignStmt:
		exprs = st.Rhs
	}
	var calls []*ast.CallExpr
	for _, e := range exprs {
		if call, ok := ast.Unparen(e).(*ast.CallExpr); ok {
			calls = append(calls, call)
		}
	}
	return calls
}

// forwardsIntoApp returns the checked methods (Type.Method) whose body is a
// forward whose call lands in pkg itself: on a free function of pkg, or on a
// method of pkg that is not itself a checked forward. Moving logic into a
// helper beside the method does not make it a forward. A call of an
// interface method is a forward, whoever declares the interface. A call
// through a function-typed field or variable that pkg assigns (funcValues)
// lands where each value it assigns does: a function or method value of pkg
// is followed like a direct call, one of another package is a forward, and
// any other value (a function literal, a parameter, a call's result) counts
// as logic in pkg, since the scan cannot say where it lands.
func forwardsIntoApp(files []*ast.File, pkg *types.Package, info *types.Info, checked map[string]bool) []string {
	forward := map[string]bool{}
	callees := map[string][]*types.Func{}
	opaque := map[string]bool{}
	values := funcValues(files, info)
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := receiverName(fn) + "." + fn.Name.Name
			if !checked[key] || !isForward(fn.Body) {
				continue
			}
			forward[key] = true
			if len(fn.Body.List) == 0 {
				continue
			}
			for _, call := range outerCalls(fn.Body.List[0]) {
				var id *ast.Ident
				switch fun := ast.Unparen(call.Fun).(type) {
				case *ast.Ident:
					id = fun
				case *ast.SelectorExpr:
					id = fun.Sel
				}
				switch callee := info.Uses[id].(type) {
				case *types.Func:
					if callee.Pkg() == pkg {
						callees[key] = append(callees[key], callee)
					}
				case *types.Var:
					assigned, ok := values[callee]
					if !ok && callee.Pkg() == pkg {
						opaque[key] = true
					}
					for _, v := range assigned {
						lands, known := landing(v, info)
						if !known {
							opaque[key] = true
						}
						for _, fn := range lands {
							if fn.Pkg() == pkg {
								callees[key] = append(callees[key], fn)
							}
						}
					}
				}
			}
		}
	}
	var into []string
	for key := range opaque {
		if forward[key] {
			delete(forward, key)
			into = append(into, key)
		}
	}
	for changed := true; changed; {
		changed = false
		for key := range forward {
			for _, callee := range callees[key] {
				recv := callee.Signature().Recv()
				if recv != nil && types.IsInterface(recv.Type()) {
					continue
				}
				if recv == nil || !forward[typeName(recv.Type())+"."+callee.Name()] {
					delete(forward, key)
					into = append(into, key)
					changed = true
					break
				}
			}
		}
	}
	slices.Sort(into)
	return into
}

// funcValues maps each function-typed field or variable that files assign,
// in a composite literal's key, on an assignment's left side or in a var
// declaration, to the values assigned to it. A field or variable files never
// assign has no entry: forwardsIntoApp counts a call through one that pkg
// declares as logic, and one another package declares and app never sets as
// a forward.
func funcValues(files []*ast.File, info *types.Info) map[*types.Var][]ast.Expr {
	values := map[*types.Var][]ast.Expr{}
	add := func(target ast.Expr, value ast.Expr) {
		var obj types.Object
		switch x := ast.Unparen(target).(type) {
		case *ast.Ident:
			obj = info.Uses[x]
			if obj == nil {
				obj = info.Defs[x]
			}
		case *ast.SelectorExpr:
			obj = info.Uses[x.Sel]
		default:
			return
		}
		v, ok := obj.(*types.Var)
		if !ok {
			return
		}
		if _, ok := v.Type().Underlying().(*types.Signature); !ok {
			return
		}
		values[v] = append(values[v], value)
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				for _, el := range n.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						add(kv.Key, kv.Value)
					}
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i := range n.Lhs {
						add(n.Lhs[i], n.Rhs[i])
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i := range n.Names {
						add(n.Names[i], n.Values[i])
					}
				}
			}
			return true
		})
	}
	return values
}

// landing is where a call through a function value lands: the function or
// method the value names, or the functions a function literal that is itself
// a forward calls (func(x T) R { return other.F(x) }). known is false for
// any other value (a literal with logic, a parameter, a call's result), whose
// landing the scan cannot say.
func landing(value ast.Expr, info *types.Info) (lands []*types.Func, known bool) {
	named := func(e ast.Expr) *types.Func {
		var id *ast.Ident
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			id = x
		case *ast.SelectorExpr:
			id = x.Sel
		}
		fn, _ := info.Uses[id].(*types.Func)
		return fn
	}
	if fn := named(value); fn != nil {
		return []*types.Func{fn}, true
	}
	lit, ok := ast.Unparen(value).(*ast.FuncLit)
	if !ok || !isForward(lit.Body) {
		return nil, false
	}
	if len(lit.Body.List) == 0 {
		return nil, true
	}
	for _, call := range outerCalls(lit.Body.List[0]) {
		fn := named(call.Fun)
		if fn == nil {
			return nil, false
		}
		if recv := fn.Signature().Recv(); recv == nil || !types.IsInterface(recv.Type()) {
			lands = append(lands, fn)
		}
	}
	return lands, true
}

// typeName is the name of t, a named type or a pointer to one.
func typeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
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
// serviceWiring (building the services) with a reason. A forward into a
// helper of app's own counts as logic (forwardsIntoApp).
func TestServiceMethodsOnlyForward(t *testing.T) {
	scan := scanApp(t)
	require.Empty(t, serviceForwardProblems(scan.files, scan.serviceMethods, scan.serviceNotForward, serviceLogic, serviceWiring))
}

// appScan is the answer of both scans of internal/app.
type appScan struct {
	files                             int
	serviceMethods, serviceNotForward []string
	portMethods, portNotForward       []string
}

// scanApp runs both scans on internal/app: the Service scan on every file,
// whatever its build constraints, and the port scan, and the check of where
// each forward lands, on the package as built for this machine.
func scanApp(t *testing.T) appScan {
	t.Helper()
	var scan appScan
	scan.files, scan.serviceMethods, scan.serviceNotForward = serviceMethods(t, ".")
	files, pkg, info, domains := loadApp(t, ".")
	ports := domainPorts(domains)
	require.NotEmpty(t, ports, "no package app reaches declares a port: the scan checks nothing")
	scan.portMethods, scan.portNotForward = portMethods(files, pkg, ports)
	checked := map[string]bool{}
	for _, key := range scan.portMethods {
		checked[key] = true
	}
	for _, name := range scan.serviceMethods {
		checked["Service."+name] = true
	}
	for _, key := range forwardsIntoApp(files, pkg, info, checked) {
		if name, ok := strings.CutPrefix(key, "Service."); ok {
			scan.serviceNotForward = append(scan.serviceNotForward, name)
		} else {
			scan.portNotForward = append(scan.portNotForward, key)
		}
	}
	return scan
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
func (s *Service) CallsLiteral() int { return func() int { n := s.x.F(); return n }() }
func (s *Service) DiscardsLiteral() { _ = (func() int { return s.x.F() })() }
func (s *Service) PassesLiteral() { s.run(func() { s.x.F() }) }
func (s *Service) PassesLongLiteral() error {
	return s.run(func() error {
		n := s.x.F()
		return check(n)
	})
}
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
	require.ElementsMatch(t, []string{"Forward", "Call", "Discard", "Assign", "CallsLiteral", "DiscardsLiteral", "PassesLiteral", "PassesLongLiteral", "TwoStatements", "OneSwitch", "Listed"}, methods)
	require.ElementsMatch(t, []string{"Assign", "CallsLiteral", "DiscardsLiteral", "PassesLongLiteral", "TwoStatements", "OneSwitch", "Listed"}, notForward)

	problems := serviceForwardProblems(files, methods, notForward,
		map[string]string{"Listed": "probe", "Gone": "probe"},
		map[string]string{"Forward": "probe"})
	require.Equal(t, []string{
		"(*Service).Assign does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).CallsLiteral does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).DiscardsLiteral does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).OneSwitch does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).PassesLongLiteral does more than forward: move the logic to the service that owns it and leave a one-line forward",
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
	"runChecker.CheckRun":               "looks the run up in the ledger and drops the run it found",
	"agentProbe.ReinstallNotice":        "reads the store's reinstalls and renders the ledger's person message",
	"pgErrors.ServerMessage":            "the setup domain's DBErrors on pgx: unwraps a Postgres server error",
	"rootConfigDir.Upsert":              "the setup domain's config writer as root: checks the directory's owner before it writes",
	"rootFiles.ReadCredential":          "the setup domain's credential files as root: reads through the checked read",
	"rootFiles.Promote":                 "the setup domain's credential files as root: checks the pending file before it renames it",
	"rootFiles.ClearSetup":              "the setup domain's credential files as root: picks the owner before it clears the setup",
	"rootFiles.Close":                   "the setup domain's credential files as root: closes both directories",
	"EngineDownServer.Abandoned":        "basalt mcp with the engine down: answers each request line itself",
	"gatedDispatcher.Dispatch":          "the pages API: refuses a request while the engine restarts",
	"sessionDispatcher.Dispatch":        "the pages API: translates the channel's request and response to the pages' types",
	"homeSource.Home":                   "the home page: caches its read for a short time",
	"vaultLinks.Live":                   "the Vault channel: converts the live relay links",
	"vaultLinks.Session":                "the Vault channel: converts a relay link and zeroes its key",
	"osHost.ResolvedExecutable":         "the OS adapter: resolves the binary's path",
	"osHost.DialogAvailable":            "the OS adapter: checks for the admin dialog",
	"osHost.AdminDialog":                "the OS adapter: runs the admin dialog",
	"osHost.SetupState":                 "the OS adapter: reads the setup page's state over HTTP",
	"osHost.EngineBuild":                "the OS adapter: reads the engine's build over HTTP",
	"osHost.ServiceRuns":                "the OS adapter: reads the service manager's runs",
	"osHost.Sudo":                       "the OS adapter: runs a command with sudo",
	"osHost.Run":                        "the OS adapter: runs a command",
	"osHost.PagesUp":                    "the OS adapter: probes the pages over HTTP",
	"osHost.Probe":                      "the OS adapter: probes the engine's socket",
	"osHost.EngineLog":                  "the OS adapter: reads the engine's log",
	"setupHost.ConnTarget":              "the setup host: parses the connection string's target",
	"setupHost.OSInstallScript":         "the setup host: reads the binary's source, then builds the install script",
	"setupHost.OSRestartScript":         "the setup host: reads the binary's source, then builds the restart script",
	"setupHost.OSOpenTrustedDir":        "the setup host: returns a nil interface on an error",
	"setupHost.OpenRootConfigDir":       "the setup host: returns a nil interface on an error",
	"setupHost.RootEngineKey":           "the setup host: unwraps the config directory before it reads the key",
	"engineCLIHost.CommandName":         "forwards to app's commandName, which picks the command's name",
	"engineCLIHost.Fail":                "forwards to app's fail, which prints a command's error",
	"engineCLIHost.ChildStarter":        "forwards to app's childStarter, which starts the engine as a child",
	"engineCLIHost.RunServiceAt":        "forwards to app's runServiceAt, the whole basalt service install command",
	"engineCLIHost.EngineLog":           "forwards to app's engineLog, which builds the engine's logger",
	"engineCLIHost.EngineDown":          "forwards to app's engineDown, which reads the config for basalt mcp with the engine down",
	"engineCLIHost.EngineStarter":       "forwards to app's engineStarter, which starts the engine for basalt mcp",
	"engineCLIHost.NewEngineDownServer": "forwards to app's NewEngineDownServer",
	"engineHost.NewRecorder":            "forwards to app's newRecorder, the crash recorder",
	"rootFiles.ReadPending":             "forwards to rootFiles.read, the checked credential read",
	"setupHost.LoadOrCreateEngineKeys":  "forwards to app's loadOrCreateEngineKeys, which reads or creates the channel keys",
	"setupHost.OpenRootCredFiles":       "forwards to app's openRootCredFiles, which opens the credential files as root",
	"setupHost.RootTrustedOwner":        "forwards to app's rootTrustedOwner, which checks the config directory's owner",
	"setupHost.ServerMessage":           "forwards to pgErrors.ServerMessage, which is listed itself",
}

// declaresPorts reports whether the package at path, in module, is one whose
// interfaces app may fill: any package under internal/ but app and testkit
// (domains, their in/ and out/ adapters, platform, core, lib, config), and
// any package under pkg/.
func declaresPorts(module, path string) bool {
	if rest, ok := strings.CutPrefix(path, module+"/internal/"); ok {
		top, _, _ := strings.Cut(rest, "/")
		return top != "app" && top != "testkit"
	}
	return strings.HasPrefix(path, module+"/pkg/")
}

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
// and the packages it reaches that declare ports (declaresPorts).
func loadApp(t *testing.T, dir string) ([]*ast.File, *types.Package, *types.Info, []*types.Package) {
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
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	pkg, err := (&types.Config{Importer: imp}).Check(self.ImportPath, fset, files, info)
	require.NoError(t, err)
	var domains []*types.Package
	for _, p := range pkgs {
		if !declaresPorts(self.Module.Path, p.ImportPath) {
			continue
		}
		d, err := imp.Import(p.ImportPath)
		require.NoError(t, err, p.ImportPath)
		domains = append(domains, d)
	}
	return files, pkg, info, domains
}

// domainPorts are the non-empty, non-generic interface types the packages
// declare.
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
		return []string{"the port scan found no app method that implements a port: it checks nothing"}
	}
	var problems []string
	for _, key := range notForward {
		if list[key] == "" {
			problems = append(problems, key+" implements a port and does more than forward: move the logic to the service that owns it and leave a one-line forward")
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
// implements an interface declared outside app (declaresPorts) is one return
// or call statement, or is listed in portLogic with a reason. The package is
// type-checked as built for this machine, so files only other platforms
// build (*_other.go) are not checked; CI runs the test on linux, and darwin
// gives the same answer. A forward into a helper of app's own counts as
// logic (forwardsIntoApp).
//
// Not covered: a method promoted from an embedded field (the embedded type's
// own methods are checked only if that type is itself a port type of app),
// calls in a forward's arguments (return s.x.F(helper(v))), a function
// literal argument of one statement that is itself an if or a switch, and a
// function-typed field set positionally in a struct literal (T{f, g}).
func TestPortMethodsOnlyForward(t *testing.T) {
	scan := scanApp(t)
	require.Empty(t, portForwardProblems(scan.portMethods, scan.portNotForward, portLogic))
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
		"logic.Tell implements a port and does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"portLogic entry gone.Ask matches no port method in app that does more than forward: remove it",
	}, portForwardProblems(methods, notForward, map[string]string{"logic.Ask": "probe", "gone.Ask": "probe"}))
	require.Equal(t, []string{"the port scan found no app method that implements a port: it checks nothing"},
		portForwardProblems(nil, nil, nil))
}

// A forward into app's own code is logic: a call of a free function of app,
// or of an app method that is not itself a checked forward. A call of
// another checked forward, of an interface method or of another package is
// a forward. A call through a function-typed field or variable lands where
// the values app assigns it do; one the scan cannot follow (a literal with
// logic, a parameter, a field app never sets) is logic.
func TestForwardIntoAppIsLogic(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "probe.go", `package app

type port interface{ Ask() int }

func helper() int { n := 1; return n }

type checked struct{ p port }

func (c checked) Ask() int { return c.p.Ask() }

type unchecked struct{}

func (unchecked) Ask() int { return 1 }

type uses struct {
	p port
	c checked
	u unchecked
	l *listed
}

func (u uses) Interface() int  { return u.p.Ask() }
func (u uses) Checked() int    { return u.c.Ask() }
func (u uses) Helper() int     { return helper() }
func (u uses) Discard()        { _ = helper() }
func (u uses) Unchecked() int  { return u.u.Ask() }
func (u uses) ViaHelper() int  { return u.Helper() }
func (u uses) Listed() int     { return u.l.Ask() }
func (u uses) InArgument() int { return max(helper(), 0) }

type listed struct{}

func (*listed) Ask() int {
	n := 1
	return n
}

type fields struct {
	helperFn, forwardFn, litFn, paramFn, methodFn, unsetFn func() int
}

var varFn = helper

func wire(p port, c checked, fn func() int) fields {
	f := fields{helperFn: helper, forwardFn: func() int { return p.Ask() }, methodFn: c.Ask}
	f.litFn = func() int { n := 1; return n }
	f.paramFn = fn
	return f
}

func (f fields) ViaHelper() int  { return f.helperFn() }
func (f fields) ViaForward() int { return f.forwardFn() }
func (f fields) ViaLiteral() int { return f.litFn() }
func (f fields) ViaParam() int   { return f.paramFn() }
func (f fields) ViaMethod() int  { return f.methodFn() }
func (f fields) ViaUnset() int   { return f.unsetFn() }
func (f fields) ViaVar() int     { return varFn() }

type Service struct{ u uses }

func (s *Service) Forward() int { return s.u.Checked() }
func (s *Service) Helper() int  { return helper() }
`, parser.SkipObjectResolution)
	require.NoError(t, err)
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	pkg, err := (&types.Config{}).Check("example.com/m/internal/app", fset, []*ast.File{f}, info)
	require.NoError(t, err)
	checked := map[string]bool{}
	for _, key := range []string{
		"checked.Ask", "uses.Interface", "uses.Checked", "uses.Helper", "uses.Discard", "uses.Unchecked",
		"uses.ViaHelper", "uses.Listed", "uses.InArgument", "listed.Ask", "Service.Forward", "Service.Helper",
		"fields.ViaHelper", "fields.ViaForward", "fields.ViaLiteral", "fields.ViaParam", "fields.ViaMethod",
		"fields.ViaUnset", "fields.ViaVar",
	} {
		checked[key] = true
	}
	require.Equal(t, []string{
		"Service.Helper", "fields.ViaHelper", "fields.ViaLiteral", "fields.ViaParam", "fields.ViaUnset", "fields.ViaVar",
		"uses.Discard", "uses.Helper", "uses.Listed", "uses.Unchecked", "uses.ViaHelper",
	}, forwardsIntoApp([]*ast.File{f}, pkg, info, checked))
}

// declaresPorts takes every package under internal/ but app and testkit,
// and pkg/.
func TestDeclaresPorts(t *testing.T) {
	const m = "example.com/m"
	for path, want := range map[string]bool{
		m + "/internal/revert":              true,
		m + "/internal/revert/in/revertmcp": true,
		m + "/internal/setup/out/credfiles": true,
		m + "/internal/platform/cli":        true,
		m + "/internal/core/guidance":       true,
		m + "/internal/lib/atomicfile":      true,
		m + "/internal/config":              true,
		m + "/pkg/setup":                    true,
		m + "/internal/app":                 false,
		m + "/internal/appendix":            true,
		m + "/internal/testkit/archtest":    false,
		m + "/cmd/basalt":                   false,
		m + "/pkgs":                         false,
		"example.com/other/internal/revert": false,
	} {
		require.Equal(t, want, declaresPorts(m, path), path)
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
