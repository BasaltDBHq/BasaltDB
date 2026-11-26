package archtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// inboundReachBaseline pins the outbound packages an inbound adapter links
// today, as "inbound -> outbound". Setup's three adapters reach the guard
// installer through pkg/setup. The list only shrinks: a new pair fails, and so
// does a pair that no longer holds.
var inboundReachBaseline = []string{
	"internal/setup/in/localsetup -> internal/platform/postgres/demo",
	"internal/setup/in/localsetup -> internal/platform/postgres/guard",
	"internal/setup/in/localsetup -> internal/platform/postgres/pglargevalue",
	"internal/setup/in/localsetup -> internal/platform/postgres/pgquerier",
	"internal/setup/in/localsetup -> internal/platform/postgres/setupstore",
	"internal/setup/in/localsetup -> internal/platform/postgres/sqlport",
	"internal/setup/in/setupcli -> internal/platform/postgres/demo",
	"internal/setup/in/setupcli -> internal/platform/postgres/guard",
	"internal/setup/in/setupcli -> internal/platform/postgres/pglargevalue",
	"internal/setup/in/setupcli -> internal/platform/postgres/pgquerier",
	"internal/setup/in/setupcli -> internal/platform/postgres/setupstore",
	"internal/setup/in/setupcli -> internal/platform/postgres/sqlport",
	"internal/setup/in/setuppage -> internal/platform/postgres/demo",
	"internal/setup/in/setuppage -> internal/platform/postgres/guard",
	"internal/setup/in/setuppage -> internal/platform/postgres/pglargevalue",
	"internal/setup/in/setuppage -> internal/platform/postgres/pgquerier",
	"internal/setup/in/setuppage -> internal/platform/postgres/setupstore",
	"internal/setup/in/setuppage -> internal/platform/postgres/sqlport",
}

// crossDomainInbound pins every import from a domain's in/ package into
// another domain (its service, its in/ or its out/). A new edge fails until it
// is listed here with its reason; a listed edge that is gone fails too.
var crossDomainInbound = []string{
	// approval tools return the pending revert the revert tools describe.
	"internal/approval/in/approvalmcp -> internal/revert/in/revertmcp",
	// the agent tools and the three pages use the link types and errors.
	"internal/agent/in/agentmcp -> internal/links",
	"internal/approval/in/approvalpage -> internal/links",
	"internal/plugin/in/pluginpage -> internal/links",
	"internal/revert/in/revertpage -> internal/links",
	// the engine CLI reads the plugin upload rule and the engine-down answer.
	"internal/engine/in/enginecli -> internal/plugin",
	"internal/engine/in/enginecli -> internal/status/in/statusmcp",
	// handoff reads setup's SQLSTATE constants and the status readiness types.
	"internal/handoff/in/handoffcli -> internal/setup",
	"internal/handoff/in/handoffmcp -> internal/status",
	// local setup asks the PII service for column suggestions.
	"internal/setup/in/localsetup -> internal/pii",
	// the setup CLI installs the engine service, reads its crash loops and the
	// handoff login refusal.
	"internal/setup/in/setupcli -> internal/engine",
	"internal/setup/in/setupcli -> internal/engine/in/enginecli",
	"internal/setup/in/setupcli -> internal/handoff",
	// status reports the engine's abandoned-run message.
	"internal/status/in/statusmcp -> internal/engine",
}

// domainOf returns the domain a path under internal/ belongs to, or "".
func domainOf(rel string) string {
	for _, d := range domains {
		if rel == "internal/"+d || strings.HasPrefix(rel, "internal/"+d+"/") {
			return d
		}
	}
	return ""
}

// inboundRoots returns the inbound packages of the graph: domain in/ packages
// and the platform inbound packages. Test helpers are left out.
func inboundRoots(graph map[string][]string) []string {
	var out []string
	for p := range graph {
		rel, ok := strings.CutPrefix(p, modulePath+"/")
		if !ok || layerOf(rel) != lInbound || slices.Contains(testHelpers, rel) {
			continue
		}
		out = append(out, rel)
	}
	slices.Sort(out)
	return out
}

// outboundReach returns, as "inbound -> outbound", every outbound package each
// inbound root links at any depth.
func outboundReach(graph map[string][]string, roots []string) []string {
	var out []string
	for _, r := range roots {
		seen := map[string]bool{}
		queue := []string{modulePath + "/" + r}
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			for _, q := range graph[p] {
				if seen[q] {
					continue
				}
				seen[q] = true
				queue = append(queue, q)
				if rel, ok := strings.CutPrefix(q, modulePath+"/"); ok && layerOf(rel) == lOutbound {
					out = append(out, r+" -> "+rel)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// crossDomainEdges returns, as "from -> to", every direct import from a
// domain's in/ package into another domain.
func crossDomainEdges(graph map[string][]string, roots []string) []string {
	var out []string
	for _, r := range roots {
		from := domainOf(r)
		if from == "" {
			continue
		}
		for _, q := range graph[modulePath+"/"+r] {
			rel, ok := strings.CutPrefix(q, modulePath+"/")
			if !ok {
				continue
			}
			if to := domainOf(rel); to != "" && to != from {
				out = append(out, r+" -> "+rel)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// pinnedDiff returns what got has beyond want and what want lists that got
// does not have.
func pinnedDiff(got, want []string) (added, stale []string) {
	for _, g := range got {
		if !slices.Contains(want, g) {
			added = append(added, g)
		}
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			stale = append(stale, w)
		}
	}
	return added, stale
}

func TestInboundChecksCatchAProbe(t *testing.T) {
	m := modulePath + "/"
	graph := map[string][]string{
		m + "internal/agent/in/agentmcp":       {m + "internal/agent", m + "internal/links", "fmt"},
		m + "internal/agent":                   {m + "pkg/setup"},
		m + "pkg/setup":                        {m + "internal/platform/postgres/guard"},
		m + "internal/platform/postgres/guard": {m + "internal/lib/x"},
		m + "internal/platform/httpserver":     {m + "internal/lib/x"},
		m + "internal/testkit/connecttest":     {m + "internal/platform/postgres/guard"},
	}
	roots := inboundRoots(graph)
	if want := []string{"internal/agent/in/agentmcp", "internal/platform/httpserver"}; !slices.Equal(roots, want) {
		t.Fatalf("roots = %q, want %q", roots, want)
	}
	got := outboundReach(graph, roots)
	if want := []string{"internal/agent/in/agentmcp -> internal/platform/postgres/guard"}; !slices.Equal(got, want) {
		t.Errorf("reach = %q, want %q", got, want)
	}
	edges := crossDomainEdges(graph, roots)
	if want := []string{"internal/agent/in/agentmcp -> internal/links"}; !slices.Equal(edges, want) {
		t.Errorf("edges = %q, want %q", edges, want)
	}
	added, stale := pinnedDiff(edges, []string{"internal/agent/in/agentmcp -> internal/plugin"})
	if len(added) != 1 || len(stale) != 1 {
		t.Errorf("pinnedDiff: added %q, stale %q; want one of each", added, stale)
	}
}

func TestInboundOnlyTranslates(t *testing.T) {
	root := moduleRoot(t)
	var reach, edges []string
	for _, goos := range []string{"linux", "darwin"} {
		graph := listGraph(t, root, goos, "...")
		roots := inboundRoots(graph)
		if len(roots) < len(domains) {
			t.Fatalf("found %d inbound packages (GOOS=%s), want at least %d", len(roots), goos, len(domains))
		}
		reach = append(reach, outboundReach(graph, roots)...)
		edges = append(edges, crossDomainEdges(graph, roots)...)
	}
	slices.Sort(reach)
	reach = slices.Compact(reach)
	slices.Sort(edges)
	edges = slices.Compact(edges)

	added, stale := pinnedDiff(reach, inboundReachBaseline)
	for _, a := range added {
		t.Errorf("an inbound adapter links an outbound adapter: %s\n\tinbound translates and calls a service; the app wires the adapter", a)
	}
	for _, s := range stale {
		t.Errorf("inboundReachBaseline lists %s, which no longer holds: remove it", s)
	}
	added, stale = pinnedDiff(edges, crossDomainInbound)
	for _, a := range added {
		t.Errorf("a new cross-domain inbound import: %s\n\tgo through a port the app fills, or list the edge in crossDomainInbound with its reason", a)
	}
	for _, s := range stale {
		t.Errorf("crossDomainInbound lists %s, which no longer exists: remove it", s)
	}
}

// inboundDriverBaseline pins the non-test files of inbound packages that
// import a database driver today, with the reason. The list only shrinks: a
// new file fails, and so does a listed file that no longer imports one.
var inboundDriverBaseline = map[string]string{
	"internal/handoff/in/handoffcli/login.go":    "maps a pgconn.PgError from the login probe to a refusal",
	"internal/platform/cli/host.go":              "its host port returns a *pgx.Conn",
	"internal/platform/cli/io.go":                "its querier port uses pgx rows and command tags",
	"internal/platform/cli/trust.go":             "parses the connection string and returns a *pgx.Conn",
	"internal/setup/in/localsetup/agentjobs.go":  "runs the agent job SQL in a transaction",
	"internal/setup/in/localsetup/backend.go":    "runs setup SQL on a pgx connection and transaction",
	"internal/setup/in/localsetup/cause.go":      "reads the SQLSTATE of a pgconn.PgError",
	"internal/setup/in/localsetup/classes.go":    "reads columns and writes labels with SQL",
	"internal/setup/in/localsetup/confirm.go":    "reads the confirm facts with SQL",
	"internal/setup/in/localsetup/doctor.go":     "runs the doctor checks with SQL",
	"internal/setup/in/localsetup/fixes.go":      "applies fixes in a transaction",
	"internal/setup/in/localsetup/localsetup.go": "checks role membership and runs setup SQL",
	"internal/setup/in/localsetup/pin.go":        "dials the pinned admin connection",
	"internal/setup/in/localsetup/repair.go":     "repairs the guard in a transaction",
	"internal/setup/in/localsetup/run.go":        "runs the setup transaction",
	"internal/setup/in/localsetup/trustfix.go":   "applies the trust fix in a transaction",
}

// driverImport reports whether an import path is a database driver: pgx and
// its subpackages, the old jackc/pgconn and pgtype modules, and database/sql.
func driverImport(p string) bool {
	return p == "github.com/jackc/pgx" || strings.HasPrefix(p, "github.com/jackc/pgx/") ||
		p == "github.com/jackc/pgconn" || strings.HasPrefix(p, "github.com/jackc/pgconn/") ||
		p == "github.com/jackc/pgtype" || strings.HasPrefix(p, "github.com/jackc/pgtype/") ||
		p == "database/sql" || strings.HasPrefix(p, "database/sql/")
}

// inboundDriverFiles returns, sorted, the non-test Go files of inbound
// packages under internal/ in fsys that import a database driver directly,
// and how many inbound files it scanned. testdata directories are skipped.
func inboundDriverFiles(t *testing.T, fsys fs.FS) (files []string, scanned int) {
	t.Helper()
	var out []string
	err := fs.WalkDir(fsys, "internal", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		dir := path.Dir(p)
		if layerOf(dir) != lInbound || slices.Contains(testHelpers, dir) {
			return nil
		}
		scanned++
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if ip, _ := strconv.Unquote(imp.Path.Value); driverImport(ip) {
				out = append(out, p)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning inbound packages: %v", err)
	}
	slices.Sort(out)
	return out, scanned
}

func TestInboundDriverCheckCatchesAProbe(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/agent/in/agentmcp/a.go":          {Data: []byte("package agentmcp\nimport \"github.com/jackc/pgx/v5/pgconn\"\n")},
		"internal/agent/in/agentmcp/a_test.go":     {Data: []byte("package agentmcp\nimport \"database/sql\"\n")},
		"internal/agent/in/agentmcp/b.go":          {Data: []byte("package agentmcp\nimport \"fmt\"\n")},
		"internal/platform/cli/c.go":               {Data: []byte("package cli\nimport sq \"database/sql\"\n")},
		"internal/platform/cli/d.go":               {Data: []byte("package cli\nimport \"github.com/jackc/pgconn\"\n")},
		"internal/platform/postgres/e.go":          {Data: []byte("package postgres\nimport \"github.com/jackc/pgx/v5\"\n")},
		"internal/agent/f.go":                      {Data: []byte("package agent\nimport \"github.com/jackc/pgtype\"\n")},
		"internal/agent/in/agentmcp/testdata/h.go": {Data: []byte("package testdata\nimport \"database/sql\"\n")},
		"internal/testkit/connecttest/g.go":        {Data: []byte("package connecttest\nimport \"database/sql\"\n")},
	}
	got, scanned := inboundDriverFiles(t, fsys)
	if scanned != 4 {
		t.Errorf("scanned %d inbound files, want 4", scanned)
	}
	want := []string{"internal/agent/in/agentmcp/a.go", "internal/platform/cli/c.go", "internal/platform/cli/d.go"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	added, stale := pinnedDiff(got, []string{"internal/platform/cli/c.go", "internal/platform/cli/gone.go"})
	if !slices.Equal(added, []string{"internal/agent/in/agentmcp/a.go", "internal/platform/cli/d.go"}) || !slices.Equal(stale, []string{"internal/platform/cli/gone.go"}) {
		t.Errorf("pinnedDiff: added %q, stale %q", added, stale)
	}
}

func TestInboundImportsNoDriver(t *testing.T) {
	got, scanned := inboundDriverFiles(t, os.DirFS(moduleRoot(t)))
	if scanned == 0 {
		t.Fatal("scanned no inbound Go files: the check would pass on nothing")
	}
	pinned := make([]string, 0, len(inboundDriverBaseline))
	for f := range inboundDriverBaseline {
		pinned = append(pinned, f)
	}
	added, stale := pinnedDiff(got, pinned)
	for _, a := range added {
		t.Errorf("an inbound file imports a database driver: %s\n\tinbound translates and calls a service; SQL belongs in an outbound adapter behind the service's port", a)
	}
	for _, s := range stale {
		t.Errorf("inboundDriverBaseline lists %s, which no longer imports a driver: remove it", s)
	}
}
