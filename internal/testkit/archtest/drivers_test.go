package archtest

import (
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// driverPkg reports whether p is a database driver package.
func driverPkg(p string) bool {
	return strings.HasPrefix(p, "github.com/jackc/") ||
		strings.HasPrefix(p, "github.com/lib/pq") ||
		strings.HasPrefix(p, "github.com/go-sql-driver/") ||
		strings.HasPrefix(p, "github.com/mattn/go-sqlite3")
}

// The one named exception to the driver-free rule: pkg/trustprofile's Trust
// and Explain take *pgconn.Config (public API); moving them to pgdial is an
// owner decision. Only that one import edge is skipped; every other import
// of pkg/trustprofile is followed.
const (
	trustprofilePkg = modulePath + "/pkg/trustprofile"
	pgconnPkg       = "github.com/jackc/pgx/v5/pgconn"
)

// driverChains returns, for the package root, every driver package a chain of
// imports reaches other than through the exception, with one such chain
// each. graph maps an import path to its imports.
func driverChains(graph map[string][]string, root string) []string {
	var out []string
	parent := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, q := range graph[p] {
			if p == trustprofilePkg && q == pgconnPkg {
				continue
			}
			if _, seen := parent[q]; seen {
				continue
			}
			parent[q] = p
			if driverPkg(q) {
				chain := q
				for c := p; c != ""; c = parent[c] {
					chain = c + " -> " + chain
				}
				out = append(out, strings.ReplaceAll(chain, modulePath+"/", ""))
				continue
			}
			queue = append(queue, q)
		}
	}
	sort.Strings(out)
	return out
}

// TestDriverChainsFollowTheRule runs the rule on a small graph: the one
// named edge passes, any other path to a driver fails, also one that goes
// through pkg/trustprofile.
func TestDriverChainsFollowTheRule(t *testing.T) {
	m := modulePath + "/"
	graph := map[string][]string{
		m + "internal/a":        {m + "pkg/trustprofile", m + "internal/lib/x"},
		m + "pkg/trustprofile":  {pgconnPkg},
		m + "internal/lib/x":    {"fmt"},
		m + "internal/b":        {m + "pkg/trustprofile", m + "internal/lib/y"},
		m + "internal/lib/y":    {"github.com/lib/pq"},
		m + "internal/c":        {m + "pkg/trustprofile2"},
		m + "pkg/trustprofile2": {pgconnPkg},
		m + "internal/d":        {m + "pkg/trustprofile"},
	}
	if got := driverChains(graph, m+"internal/a"); len(got) != 0 {
		t.Errorf("the named edge alone must pass; got %q", got)
	}
	got := driverChains(graph, m+"internal/b")
	want := "internal/b -> internal/lib/y -> github.com/lib/pq"
	if len(got) != 1 || got[0] != want {
		t.Errorf("got %q, want [%q]", got, want)
	}
	if got := driverChains(graph, m+"internal/c"); len(got) != 1 {
		t.Errorf("another package's pgconn import must fail; got %q", got)
	}

	// The rest of pkg/trustprofile is still walked.
	graph[m+"pkg/trustprofile"] = []string{pgconnPkg, m + "internal/lib/x"}
	graph[m+"internal/lib/x"] = []string{"github.com/jackc/pgx/v5/pgxpool"}
	got = driverChains(graph, m+"internal/d")
	want = "internal/d -> pkg/trustprofile -> internal/lib/x -> github.com/jackc/pgx/v5/pgxpool"
	if len(got) != 1 || got[0] != want {
		t.Errorf("got %q, want [%q]", got, want)
	}
}

// listGraph is the import graph under dir's package ./internal/<d> for goos.
func listGraph(t *testing.T, root, goos, d string) map[string][]string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./internal/"+d)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./internal/%s (GOOS=%s) failed: %v\n%s", d, goos, err, raw)
	}
	graph := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			graph[f[0]] = f[1:]
		}
	}
	return graph
}

// TestServicesLinkNoDatabaseDriver fails when a service package (a domain
// root, internal/<d>) has a database driver among its transitive imports on
// linux or darwin, other than through the one named edge. A go list that
// fails fails the test.
func TestServicesLinkNoDatabaseDriver(t *testing.T) {
	root := moduleRoot(t)
	checked := 0
	for _, goos := range []string{"linux", "darwin"} {
		for _, d := range domains {
			graph := listGraph(t, root, goos, d)
			pkg := modulePath + "/internal/" + d
			if _, ok := graph[pkg]; !ok {
				t.Fatalf("go list -deps ./internal/%s (GOOS=%s) did not list the package itself", d, goos)
			}
			checked++
			for _, chain := range driverChains(graph, pkg) {
				t.Errorf("a service links a database driver (GOOS=%s): %s\n\tuse a port the service declares and an adapter that implements it", goos, chain)
			}
		}
	}
	if want := 2 * len(domains); checked != want {
		t.Fatalf("checked %d service roots, want %d", checked, want)
	}
}
