package archtest

import (
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

// trustprofilePkg is the one named exception to the driver-free rule:
// pkg/trustprofile's Trust and Explain take *pgconn.Config (public API);
// moving them to pgdial is an owner decision.
const trustprofilePkg = modulePath + "/pkg/trustprofile"

// driverChains returns, for the package root, every driver package a chain of
// imports reaches without passing through the exception, with one such chain
// each. graph maps an import path to its imports.
func driverChains(graph map[string][]string, root string) []string {
	var out []string
	parent := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if p == trustprofilePkg {
			continue
		}
		for _, q := range graph[p] {
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

// TestDriverChainsFollowTheRule runs the rule on a small graph: a driver
// through the named exception passes, any other path fails.
func TestDriverChainsFollowTheRule(t *testing.T) {
	m := modulePath + "/"
	graph := map[string][]string{
		m + "internal/a":       {m + "pkg/trustprofile", m + "internal/lib/x"},
		m + "pkg/trustprofile": {"github.com/jackc/pgx/v5/pgconn"},
		m + "internal/lib/x":   {"fmt"},
		m + "internal/b":       {m + "pkg/trustprofile", m + "internal/lib/y"},
		m + "internal/lib/y":   {"github.com/lib/pq"},
	}
	if got := driverChains(graph, m+"internal/a"); len(got) != 0 {
		t.Errorf("a driver through pkg/trustprofile alone must pass; got %q", got)
	}
	got := driverChains(graph, m+"internal/b")
	want := "internal/b -> internal/lib/y -> github.com/lib/pq"
	if len(got) != 1 || got[0] != want {
		t.Errorf("got %q, want [%q]", got, want)
	}
}

// TestServicesLinkNoDatabaseDriver fails when a service package (a domain
// root, internal/<d>) has a database driver among its transitive imports,
// other than through pkg/trustprofile.
func TestServicesLinkNoDatabaseDriver(t *testing.T) {
	root := moduleRoot(t)
	for _, d := range domains {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./internal/"+d)
		cmd.Dir = root
		raw, err := cmd.Output()
		if err != nil {
			continue // the domain has no package yet
		}
		graph := map[string][]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 {
				graph[f[0]] = f[1:]
			}
		}
		for _, chain := range driverChains(graph, modulePath+"/internal/"+d) {
			t.Errorf("a service links a database driver: %s\n\tuse a port the service declares and an adapter that implements it", chain)
		}
	}
}
