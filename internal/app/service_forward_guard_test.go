package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
// statement. One if, switch or loop is not a forward, however short.
func isForward(body *ast.BlockStmt) bool {
	switch len(body.List) {
	case 0:
		return true
	case 1:
		switch body.List[0].(type) {
		case *ast.ReturnStmt, *ast.ExprStmt:
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
	require.ElementsMatch(t, []string{"Forward", "Call", "TwoStatements", "OneSwitch", "Listed"}, methods)
	require.ElementsMatch(t, []string{"TwoStatements", "OneSwitch", "Listed"}, notForward)

	problems := serviceForwardProblems(files, methods, notForward,
		map[string]string{"Listed": "probe", "Gone": "probe"},
		map[string]string{"Forward": "probe"})
	require.Equal(t, []string{
		"(*Service).OneSwitch does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"(*Service).TwoStatements does more than forward: move the logic to the service that owns it and leave a one-line forward",
		"serviceLogic entry Gone matches no method on Service that does more than forward: remove it",
		"serviceWiring entry Forward matches no method on Service that does more than forward: remove it",
	}, problems)

	files, methods, notForward = serviceMethods(t, t.TempDir())
	require.Equal(t, []string{"the scan read no file or found no method on Service: it checks nothing"},
		serviceForwardProblems(files, methods, notForward, nil, nil))
}
