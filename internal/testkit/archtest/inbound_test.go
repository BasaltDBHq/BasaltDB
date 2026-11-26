package archtest

import (
	"slices"
	"strings"
	"testing"
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
