package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// storeRule is what a store-neutral domain's root package (its non-test
// files) may not hold: imports of a store's packages, identifiers and
// string texts that name a store's own things, and selectors of the shared
// packages that read a store's answers.
type storeRule struct {
	dir     string
	imports []string
	ident   *regexp.Regexp
	text    *regexp.Regexp
	// selectors are, by import path, the names of that package the domain
	// may not use. They are matched on the selector, resolved through the
	// file's imports, so an alias does not hide one.
	selectors map[string]*regexp.Regexp
	// allowed are findings that may stay, each with its reason.
	allowed map[string]string
	// allowedDeps are store packages the domain may still reach through
	// another package, by import path, each with its reason.
	allowedDeps map[string]string
	// throughTrustprofile skips the one named edge of the driver-free rule
	// (pkg/trustprofile's pgconn, drivers_test.go) for a domain that reaches
	// pkg/trustprofile; every other import of it is followed.
	throughTrustprofile bool
}

// storeBoundImports are a store's packages: the SQL guard, the Postgres
// adapters (with their query port and the large-value SQL) and the driver.
// A store-neutral domain imports none of them, directly or through another
// package.
var storeBoundImports = []string{
	modulePath + "/internal/core/sqlguard",
	modulePath + "/internal/platform/postgres",
	"github.com/jackc/pgx",
	"github.com/jackc/pgconn",
	"github.com/Masterminds/squirrel",
}

// storeBound reports whether p is one of storeBoundImports or below one.
func storeBound(p string) bool {
	return slices.ContainsFunc(storeBoundImports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") })
}

// agentStoreRule holds internal/agent to its store's ports, as its
// siblings are held: it decides on the store's typed answers, never on a
// store's catalog numbers, statements, SQLSTATEs, or the guard's codes and
// details.
var agentStoreRule = storeRule{
	dir:     filepath.Join("internal", "agent"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`SQLState|OID|Oid|Attnum|attnum|pg_`),
	// A SQLSTATE is five digits or capitals starting with a digit, such as
	// 42P01.
	text: regexp.MustCompile(`\$[0-9]|pg_|\b[0-9][0-9A-Z]{4}\b`),
	selectors: map[string]*regexp.Regexp{
		modulePath + "/internal/core/guidance":   regexp.MustCompile(`^(LedgerCode|StoreDetail|StoreError|TimedOut)$`),
		modulePath + "/internal/core/guardmodel": regexp.MustCompile(`^(Code.*|Detail.*|UnpickedGrantsDetail)$`),
		modulePath + "/internal/core/action":     regexp.MustCompile(`^StoreError$`),
	},
	allowed:     map[string]string{},
	allowedDeps: map[string]string{},
}

// revertStoreRule holds internal/revert to its store's ports: it decides on
// the store's typed refusals, never on the guard's codes, details or
// SQLSTATEs.
var revertStoreRule = storeRule{
	dir:     filepath.Join("internal", "revert"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`SQLState|OID|Oid|xmin|pg_`),
	// A SQLSTATE is five digits or capitals starting with a digit, such as
	// 57014; the domain reads the store's codes only through its ports.
	text: regexp.MustCompile(`pg_|xmin|\b[0-9][0-9A-Z]{4}\b`),
	selectors: map[string]*regexp.Regexp{
		modulePath + "/internal/core/guidance":   regexp.MustCompile(`^(LedgerCode|StoreDetail|TimedOut)$`),
		modulePath + "/internal/core/guardmodel": regexp.MustCompile(`^(Code.*|Scope.*|.*Refused|Detail.*|UnpickedGrantsDetail)$`),
		modulePath + "/internal/core/action":     regexp.MustCompile(`^StoreError$`),
	},
	allowed:     map[string]string{},
	allowedDeps: map[string]string{},
}

// piiStoreRule holds internal/pii to its store's ports (Classes, Fields and
// the sampler): it never names a store's catalog, keys, row positions or
// error codes, and never writes a statement.
var piiStoreRule = storeRule{
	dir:     filepath.Join("internal", "pii"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`OID|Oid|Attnum|attnum|SQLState|relkind|ctid|pg_`),
	// A SQLSTATE is five digits or capitals starting with a digit, such as
	// 42P01.
	text:        regexp.MustCompile(`pg_|basalt_meta|\$[0-9]|\b[0-9][0-9A-Z]{4}\b`),
	allowed:     map[string]string{},
	allowedDeps: map[string]string{},
}

// approvalStoreRule holds internal/approval to its store's ports: it
// decides on the store's typed refusals
// (approvalstore.ApprovalRefusalError), never on the guard's codes or
// details, and passes the held request on unread,
// so it never names the SQL family or its sql argument. CodeStoreError,
// which the service answers for a write that changes no rows now, stays:
// the selectors match exact names.
var approvalStoreRule = storeRule{
	dir:     filepath.Join("internal", "approval"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`SQLState|OID|pg_`),
	text:    regexp.MustCompile(`pg_|^(?i:sql)$`),
	selectors: map[string]*regexp.Regexp{
		modulePath + "/internal/core/guidance":   regexp.MustCompile(`^(LedgerCode|StoreDetail|StoreError)$`),
		modulePath + "/internal/core/guardmodel": regexp.MustCompile(`^(Code.*|.*Refused|Reveal.*|Detail.*|UnpickedGrantsDetail)$`),
		modulePath + "/internal/core/approval":   regexp.MustCompile(`^RequestSQL$`),
		modulePath + "/internal/core/action":     regexp.MustCompile(`^StoreError$`),
	},
	allowed:     map[string]string{},
	allowedDeps: map[string]string{},
}

// in is rule r on the package in dir, with no allowlists of its own.
func (r storeRule) in(dir string) storeRule {
	r.dir, r.allowed, r.allowedDeps = dir, map[string]string{}, map[string]string{}
	return r
}

// actionStoreRule holds internal/core/action, the types every domain's
// store ports speak, to the store's opaque refs: a read's columns and row
// versions name fields and resources by FieldRef and ResourceRef, never by
// a store's own numbers.
var actionStoreRule = storeRule{
	dir:         filepath.Join("internal", "core", "action"),
	imports:     storeBoundImports,
	ident:       regexp.MustCompile(`OID|Oid|Attnum|attnum|pg_`),
	text:        regexp.MustCompile(`pg_`),
	allowed:     map[string]string{},
	allowedDeps: map[string]string{},
}

// portTypeStoreRules hold the approval's and the revert's store port types
// (internal/core/approvalstore, internal/core/revertstore) to the action
// types' rule: they left internal/core/action, not the rule.
var portTypeStoreRules = []storeRule{
	actionStoreRule.in(filepath.Join("internal", "core", "approvalstore")),
	actionStoreRule.in(filepath.Join("internal", "core", "revertstore")),
}

// pluginStoreRule holds internal/plugin, the plugin host, to its guard port:
// it decides on the store's typed answers (pluginmodel.StoreError and
// ApprovalRefusalError), never on a store's error codes, the guard's codes
// or details, or a store's own text layout, and names the store's kind only
// as the port gives it.
var pluginStoreRule = storeRule{
	dir:     filepath.Join("internal", "plugin"),
	imports: storeBoundImports,
	ident:   regexp.MustCompile(`(?i:sqlstate|jsonb)|OID|Oid|pg_`),
	// A SQLSTATE is five digits or capitals starting with a digit, such as
	// 42P01, or the guard's own BS007.
	text: regexp.MustCompile(`pg_|(?i:sqlstate|jsonb)|\b[0-9][0-9A-Z]{4}\b|\bBS[0-9]{3}\b`),
	selectors: map[string]*regexp.Regexp{
		modulePath + "/internal/core/guidance":   regexp.MustCompile(`^(LedgerCode|StoreDetail|StoreError|TimedOut)$`),
		modulePath + "/internal/core/guardmodel": regexp.MustCompile(`^(Code.*|Scope.*|Detail.*|UnpickedGrantsDetail)$`),
		modulePath + "/internal/core/action":     regexp.MustCompile(`^(StoreError|StorePostgres)$`),
	},
	allowed: map[string]string{
		`manifest.go: text "resources.memoryMB must be a whole number from 64 to 65536"`: "a memory bound in MB, not a store code",
		`feed_events.go: text "2006-01-02T15:04:05.999999Z"`:                             "Go's time layout for the feed's RFC 3339 times, not a store code",
	},
	allowedDeps: map[string]string{},
	// The plugin host reaches pkg/trustprofile through internal/status.
	throughTrustprofile: true,
}

// domainStoreRules are the store-neutral domains' roots. Each rule also
// holds every inbound adapter of its domain (inboundStoreRules).
var domainStoreRules = []storeRule{agentStoreRule, revertStoreRule, piiStoreRule, approvalStoreRule, pluginStoreRule}

// storeRules are the store-neutral packages: the domain roots, the shared
// action types and the approval's and revert's port types. inboundStoreRules
// adds the domains' in/ packages.
var storeRules = append([]storeRule{agentStoreRule, revertStoreRule, piiStoreRule, approvalStoreRule, actionStoreRule, pluginStoreRule}, portTypeStoreRules...)

// inboundAllowed are the findings an inbound adapter may keep, by its
// directory, each with its reason.
var inboundAllowed = map[string]map[string]string{
	"internal/agent/in/agentmcp": {
		"tools.go: text `json:\"sql\" validate:\"required,max=16384\"`":       "the query tool's statement length limit, not a SQLSTATE",
		"write_tools.go: text `json:\"sql\" validate:\"required,max=16384\"`": "the write tool's statement length limit, not a SQLSTATE",
	},
}

// inboundStoreRules is each store-neutral domain's rule on each of its
// inbound adapters (internal/<domain>/in/*), read from the tree, so a new
// adapter is held without a list to keep.
func inboundStoreRules(t *testing.T) []storeRule {
	t.Helper()
	root := moduleRoot(t)
	var out []storeRule
	defer func() {
		for dir := range inboundAllowed {
			if !slices.ContainsFunc(out, func(r storeRule) bool { return filepath.ToSlash(r.dir) == dir }) {
				t.Errorf("inboundAllowed names %s, which is no inbound adapter of a store-neutral domain; remove it", dir)
			}
		}
	}()
	for _, r := range domainStoreRules {
		entries, err := os.ReadDir(filepath.Join(root, r.dir, "in"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				rule := r.in(filepath.Join(r.dir, "in", e.Name()))
				if allowed, ok := inboundAllowed[filepath.ToSlash(rule.dir)]; ok {
					rule.allowed = allowed
				}
				out = append(out, rule)
			}
		}
	}
	return out
}

// importName is the name a file refers to the import s by.
func importName(s *ast.ImportSpec) string {
	if s.Name != nil {
		return s.Name.Name
	}
	p := importPath(s)
	name := path.Base(p)
	if len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
		name = path.Base(path.Dir(p))
	}
	return name
}

func storeNeutralFindings(dir string, rule storeRule) ([]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	files := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, 0, err
		}
		files++
		add := func(what string) { out = append(out, n+": "+what) }
		banned := map[string]*regexp.Regexp{}
		for _, s := range f.Imports {
			p := importPath(s)
			if slices.ContainsFunc(rule.imports, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") }) {
				add("import " + p)
			}
			if re, ok := rule.selectors[p]; ok {
				banned[importName(s)] = re
			}
		}
		ast.Inspect(f, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.ImportSpec:
				return false // checked above
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok {
					if re, ok := banned[pkg.Name]; ok && re.MatchString(x.Sel.Name) {
						add("selector " + pkg.Name + "." + x.Sel.Name)
					}
				}
			case *ast.Ident:
				if rule.ident.MatchString(x.Name) {
					add("identifier " + x.Name)
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					break
				}
				if v, err := strconv.Unquote(x.Value); err == nil && rule.text.MatchString(v) {
					add("text " + x.Value)
				}
			}
			return true
		})
	}
	slices.Sort(out)
	return slices.Compact(out), files, nil
}

func checkStoreNeutral(findings []string, allowed map[string]string) []string {
	var out []string
	for _, f := range findings {
		if _, ok := allowed[f]; !ok {
			out = append(out, f)
		}
	}
	for entry, reason := range allowed {
		if strings.TrimSpace(reason) == "" {
			out = append(out, fmt.Sprintf("allowlist entry %q has no reason", entry))
		}
		if !slices.Contains(findings, entry) {
			out = append(out, fmt.Sprintf("allowlist entry %q matches nothing; remove it", entry))
		}
	}
	slices.Sort(out)
	return out
}

// requireStoreNeutral checks rule on the module's tree: it fails when it
// scans no file, on a finding the allowlist does not name, and on an
// allowlist entry with no reason or no finding.
func requireStoreNeutral(t *testing.T, rule storeRule, hint string) {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), rule.dir)
	findings, files, err := storeNeutralFindings(dir, rule)
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatalf("scanned no Go file in %s: the rule checks nothing", rule.dir)
	}
	for _, p := range checkStoreNeutral(findings, rule.allowed) {
		t.Errorf("%s: %s\n\t%s", rule.dir, p, hint)
	}
}

// storeChains walks graph (package to its imports) from root and returns
// each store package it reaches, with the shortest import chain to it. It
// does not walk past a store package. With throughTrustprofile it skips
// the one named edge of the driver-free rule (pkg/trustprofile's pgconn,
// drivers_test.go); every other import of pkg/trustprofile is followed.
func storeChains(graph map[string][]string, root string, throughTrustprofile bool) map[string]string {
	out := map[string]string{}
	parent := map[string]string{root: ""}
	queue := []string{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, q := range graph[p] {
			if throughTrustprofile && p == trustprofilePkg && q == pgconnPkg {
				continue
			}
			if _, seen := parent[q]; seen {
				continue
			}
			parent[q] = p
			if storeBound(q) {
				chain := q
				for c := p; c != ""; c = parent[c] {
					chain = c + " -> " + chain
				}
				out[q] = strings.ReplaceAll(chain, modulePath+"/", "")
				continue
			}
			queue = append(queue, q)
		}
	}
	return out
}

// requireNoStoreDeps checks that rule's root package reaches no store
// package through its imports, on linux and darwin: it fails when go list
// does not list the package, on a store package the allowlist does not
// name, and on an allowlist entry with no reason or no finding.
func requireNoStoreDeps(t *testing.T, rule storeRule) {
	t.Helper()
	root := moduleRoot(t)
	rel := strings.TrimPrefix(filepath.ToSlash(rule.dir), "internal/")
	pkg := modulePath + "/internal/" + rel
	for _, goos := range []string{"linux", "darwin"} {
		graph := listGraph(t, root, goos, rel)
		if _, ok := graph[pkg]; !ok {
			t.Fatalf("go list -deps ./internal/%s (GOOS=%s) did not list the package itself: the check reads nothing", rel, goos)
		}
		chains := storeChains(graph, pkg, rule.throughTrustprofile)
		found := make([]string, 0, len(chains))
		for p := range chains {
			found = append(found, p)
		}
		slices.Sort(found)
		for _, problem := range checkStoreNeutral(found, rule.allowedDeps) {
			if chain, ok := chains[problem]; ok {
				problem = chain
			}
			t.Errorf("%s reaches a store package (GOOS=%s): %s\n\tthe domain reaches its store only through its ports; move the store code into the store's adapter", rule.dir, goos, problem)
		}
	}
}

// The store-neutral domains reach no store package, directly or through
// another package.
func TestStoreNeutralDomainsLinkNoStorePackage(t *testing.T) {
	for _, rule := range slices.Concat(storeRules, inboundStoreRules(t), storeDepRules) {
		t.Run(filepath.Base(rule.dir), func(t *testing.T) { requireNoStoreDeps(t, rule) })
	}
}

// The chain search finds a store package however deep, gives the shortest
// chain, stops at the store package, and leaves a name that only starts
// like one alone.
func TestStoreChainsFollowTheRule(t *testing.T) {
	m := modulePath + "/"
	sq := "github.com/Masterminds/squirrel"
	graph := map[string][]string{
		m + "internal/a":                       {"fmt", m + "internal/lib/x", m + "internal/lib/y"},
		m + "internal/lib/x":                   {m + "internal/lib/z"},
		m + "internal/lib/z":                   {sq},
		m + "internal/lib/y":                   {sq, m + "internal/core/sqlguardian"},
		sq:                                     {"github.com/lann/builder"},
		m + "internal/core/sqlguardian":        {"fmt"},
		m + "internal/b":                       {m + "internal/lib/w"},
		m + "internal/lib/w":                   {m + "internal/platform/postgres/pgpii", "github.com/jackc/pgx/v5/pgconn"},
		m + "internal/platform/postgres/pgpii": {m + "internal/platform/postgres/sqlport"},
		m + "internal/c":                       {"fmt", m + "internal/core/piistore"},
		m + "internal/d":                       {m + "pkg/trustprofile"},
		m + "pkg/trustprofile":                 {pgconnPkg, m + "internal/lib/z"},
	}
	got := storeChains(graph, m+"internal/a", false)
	want := map[string]string{sq: "internal/a -> internal/lib/y -> " + sq}
	if !maps.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	got = storeChains(graph, m+"internal/b", false)
	want = map[string]string{
		m + "internal/platform/postgres/pgpii": "internal/b -> internal/lib/w -> internal/platform/postgres/pgpii",
		"github.com/jackc/pgx/v5/pgconn":       "internal/b -> internal/lib/w -> github.com/jackc/pgx/v5/pgconn",
	}
	if !maps.Equal(got, want) {
		t.Errorf("got %q, want %q (the walk stops at a store package)", got, want)
	}
	if got := storeChains(graph, m+"internal/c", false); len(got) != 0 {
		t.Errorf("a clean graph must pass; got %q", got)
	}
	got = storeChains(graph, m+"internal/d", true)
	want = map[string]string{sq: "internal/d -> pkg/trustprofile -> internal/lib/z -> " + sq}
	if !maps.Equal(got, want) {
		t.Errorf("got %q, want %q (only trustprofile's pgconn edge is skipped)", got, want)
	}
	got = storeChains(graph, m+"internal/d", false)
	want = map[string]string{
		pgconnPkg: "internal/d -> pkg/trustprofile -> " + pgconnPkg,
		sq:        "internal/d -> pkg/trustprofile -> internal/lib/z -> " + sq,
	}
	if !maps.Equal(got, want) {
		t.Errorf("got %q, want %q (a rule without the exception follows the edge)", got, want)
	}
}

func TestAgentDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, agentStoreRule,
		"the agent domain reaches its store only through its ports; put store code in an adapter (internal/agent/out/...) or the wiring")
}

func TestActionTypesAreStoreNeutral(t *testing.T) {
	for _, rule := range append([]storeRule{actionStoreRule}, portTypeStoreRules...) {
		t.Run(filepath.Base(rule.dir), func(t *testing.T) {
			requireStoreNeutral(t, rule,
				"the action types and the approval's and revert's port types name a store's fields and resources by "+
					"action.FieldRef and action.ResourceRef; the store's adapter writes and reads them "+
					"(for Postgres, internal/platform/postgres/agentcatalog)")
		})
	}
}

func TestPIIDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, piiStoreRule,
		"the pii domain reaches its store only through Classes, Fields and the sampler; "+
			"put store code in the store's adapter (for Postgres, internal/platform/postgres/pgpii)")
}

func TestRevertDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, revertStoreRule,
		"the revert domain reaches its store only through Records, Undo and Proofs and decides on revertstore.RevertRefusalError; "+
			"map the store's answers in its adapter (for Postgres, internal/platform/postgres/store/revert.go)")
}

func TestPluginDomainIsStoreNeutral(t *testing.T) {
	requireStoreNeutral(t, pluginStoreRule,
		"the plugin host reaches the agents' stores only through its Guard port and the plugin approval store, and decides on "+
			"pluginmodel.StoreError and pluginmodel.ApprovalRefusalError; map the store's answers in its adapter "+
			"(for Postgres, internal/platform/postgres/pluginledger and internal/platform/postgres/store/approvals.go)")
}

func TestApprovalDomainIsStoreNeutral(t *testing.T) {
	const hint = "the approval domain reaches its store only through Records, Holds and Proofs, decides on approvalstore.ApprovalRefusalError " +
		"and passes the held request on unread; map the store's answers in its adapter (for Postgres, internal/platform/postgres/store/approvals.go)"
	requireStoreNeutral(t, approvalStoreRule, hint)
}

// A store-neutral domain's inbound adapters are held to its rule: the
// approval tools pass the held request's family on from the held write,
// and no tool or page names a store's codes.
func TestStoreNeutralInboundAdapters(t *testing.T) {
	rules := inboundStoreRules(t)
	for _, want := range []string{"agentmcp", "approvalmcp", "approvalpage", "revertmcp", "revertpage", "pluginmcp", "pluginpage"} {
		if !slices.ContainsFunc(rules, func(r storeRule) bool { return filepath.Base(r.dir) == want }) {
			t.Errorf("no store rule holds %s: the inbound rules are read from internal/<domain>/in", want)
		}
	}
	for _, rule := range rules {
		t.Run(filepath.Base(rule.dir), func(t *testing.T) {
			requireStoreNeutral(t, rule, "an inbound adapter of a store-neutral domain translates the domain's typed answers; it names no store's codes, texts or packages")
		})
	}
}

func TestStoreNeutralRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	_ "github.com/jackc/pgx/v5"
	_ "` + modulePath + `/internal/core/sqlguard"
	_ "` + modulePath + `/internal/platform/postgres/pgdial"
	_ "` + modulePath + `/internal/core/sqlguardian"
)

type ref struct{ TableOID uint32; attnum int16 }

const q = "SELECT x FROM t WHERE id = $1"
const c = "pg_catalog"
const fine = "costs $ 5"
`,
		"a_test.go": `package a

const ignored = "$1 pg_class"
`,
	})
	findings, files, err := storeNeutralFindings(dir, agentStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1 (test files are left out)", files)
	}
	want := []string{
		`a.go: identifier TableOID`,
		`a.go: identifier attnum`,
		`a.go: import ` + modulePath + `/internal/core/sqlguard`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pgdial`,
		`a.go: import github.com/jackc/pgx/v5`,
		`a.go: text "SELECT x FROM t WHERE id = $1"`,
		`a.go: text "pg_catalog"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}

	allowed := map[string]string{
		`a.go: text "pg_catalog"`: "a reason",
		`a.go: identifier attnum`: " ",
		`a.go: gone`:              "it was removed",
	}
	got := checkStoreNeutral(findings, allowed)
	wantProblems := []string{
		`a.go: identifier TableOID`,
		`a.go: import ` + modulePath + `/internal/core/sqlguard`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pgdial`,
		`a.go: import github.com/jackc/pgx/v5`,
		`a.go: text "SELECT x FROM t WHERE id = $1"`,
		`allowlist entry "a.go: gone" matches nothing; remove it`,
		`allowlist entry "a.go: identifier attnum" has no reason`,
	}
	if !slices.Equal(got, wantProblems) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantProblems, "\n"))
	}
}

// The revert rule reads the shared packages' selectors through the file's
// imports, an alias too, and leaves the revert's own names alone: its
// refusal reasons, its scopes, and the guard's outcome and limit names.
func TestRevertStoreRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	"` + modulePath + `/internal/core/action"
	gm "` + modulePath + `/internal/core/guardmodel"
	"` + modulePath + `/internal/core/guidance"
	"` + modulePath + `/internal/core/revert"
	"` + modulePath + `/internal/core/revertstore"
	"` + modulePath + `/internal/core/toolresult"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	_ = gm.CodeScopeRefused
	_ = gm.ScopeShape
	_ = gm.RevertWidenRefused
	_ = gm.DetailTooManyPending
	_ = gm.UnpickedGrantsDetail
	_ = guidance.LedgerCode
	_ = guidance.TimedOut
	_ *action.StoreError
	_ *pgconn.PgError
	_ = toolresult.ToolError{SQLState: "57014"}
	_ = "SELECT xmin FROM t"
	_ = "canceled (SQLSTATE 40P01)"

	// Allowed: the revert's own names.
	_ = guidance.CodeNotFound
	_ = gm.OutcomePending
	_ = gm.MaxRejectNote
	_ = revertstore.RevertTimedOut
	_ = revertstore.RevertWidenRefused
	_ = revert.ScopeRun
	_ *revertstore.RevertRefusalError
	_ = "at most 20 runs and 1000 lines"
	_ = "id 123456, ref abc12345, version v0.1.0"
	_ = "0193b2c4-57a1-7c3e-9f2d-5e8a1b4c6d7f"
)

func scopeRefused() {}
func widenRefused() {}
`,
	})
	findings, files, err := storeNeutralFindings(dir, revertStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1", files)
	}
	want := []string{
		`a.go: identifier SQLState`,
		`a.go: import github.com/jackc/pgx/v5/pgconn`,
		`a.go: selector action.StoreError`,
		`a.go: selector gm.CodeScopeRefused`,
		`a.go: selector gm.DetailTooManyPending`,
		`a.go: selector gm.RevertWidenRefused`,
		`a.go: selector gm.ScopeShape`,
		`a.go: selector gm.UnpickedGrantsDetail`,
		`a.go: selector guidance.LedgerCode`,
		`a.go: selector guidance.TimedOut`,
		`a.go: text "57014"`,
		`a.go: text "SELECT xmin FROM t"`,
		`a.go: text "canceled (SQLSTATE 40P01)"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
}

// The pii rule finds the store's packages, catalog words, statements and
// codes, and leaves the classifier's own words and numbers alone.
func TestPIIStoreRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	sq "github.com/Masterminds/squirrel"
	_ "` + modulePath + `/internal/platform/postgres/sqlport"
	_ "` + modulePath + `/internal/platform/postgres/pgquerier"
)

type col struct{ TableOid uint32; relkind string }

var (
	_   = sq.Select
	_   = "SELECT email FROM basalt_meta.agent_pii_columns WHERE ctid > $1"
	_   = "undefined table (SQLSTATE 42P01)"
	ctid = 0

	// Allowed: the classifier's own words and numbers.
	_ = "email"
	_ = "at most 1000 values"
	_ = "+372 5555 1234"
	_ = "kind of a void field"
)
`,
	})
	findings, files, err := storeNeutralFindings(dir, piiStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1", files)
	}
	want := []string{
		`a.go: identifier TableOid`,
		`a.go: identifier ctid`,
		`a.go: identifier relkind`,
		`a.go: import github.com/Masterminds/squirrel`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pgquerier`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/sqlport`,
		`a.go: text "SELECT email FROM basalt_meta.agent_pii_columns WHERE ctid > $1"`,
		`a.go: text "undefined table (SQLSTATE 42P01)"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
}

// The plugin rule catches each ban, through an alias too, and leaves the
// plugin host's own names alone: the ledger's kinds, the approval
// statuses, the store kind type and the plugin's typed answers.
func TestPluginStoreRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	"` + modulePath + `/internal/core/action"
	gm "` + modulePath + `/internal/core/guardmodel"
	"` + modulePath + `/internal/core/guidance"
	"` + modulePath + `/internal/core/pluginmodel"
	_ "` + modulePath + `/internal/platform/postgres/pluginledger"
	_ "github.com/jackc/pgx/v5/pgconn"
)

const sqlstateUndefinedFunction = "42883"

var (
	_ = guidance.LedgerCode
	_ = guidance.StoreDetail
	_ = gm.DetailTooManyPending
	_ = action.StorePostgres
	_ *action.StoreError
	_ = "BS007"
	_ = "SQLSTATE "
	_ = "as Postgres prints jsonb"

	// Allowed: the plugin host's own names.
	_ = gm.KindRefused
	_ = gm.PluginApprovalStatusCancelled
	_ action.StoreKind
	_ *pluginmodel.StoreError
	_ = pluginmodel.ApprovalCancelled
	_ = guidance.CodeApprovalInvalid
	_ = "TOO_MANY_PENDING"
)

func jsonbSpaces() {}
`,
	})
	findings, files, err := storeNeutralFindings(dir, pluginStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1", files)
	}
	want := []string{
		`a.go: identifier jsonbSpaces`,
		`a.go: identifier sqlstateUndefinedFunction`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/pluginledger`,
		`a.go: import github.com/jackc/pgx/v5/pgconn`,
		`a.go: selector action.StoreError`,
		`a.go: selector action.StorePostgres`,
		`a.go: selector gm.DetailTooManyPending`,
		`a.go: selector guidance.LedgerCode`,
		`a.go: selector guidance.StoreDetail`,
		`a.go: text "42883"`,
		`a.go: text "BS007"`,
		`a.go: text "SQLSTATE "`,
		`a.go: text "as Postgres prints jsonb"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
}

// The approval rule catches each ban, through an alias too, and matches
// names exactly: guidance.CodeStoreError, guardmodel.MaxHeldLinesBytes, the
// approval's own refusal reasons and a word that only contains sql pass.
func TestApprovalStoreRuleCatchesViolations(t *testing.T) {
	dir := fixture(t, map[string]string{
		"a.go": `package a

import (
	"` + modulePath + `/internal/core/action"
	"` + modulePath + `/internal/core/approval"
	"` + modulePath + `/internal/core/approvalstore"
	gm "` + modulePath + `/internal/core/guardmodel"
	g "` + modulePath + `/internal/core/guidance"
	"` + modulePath + `/internal/core/toolresult"
	_ "` + modulePath + `/internal/core/sqlguard"
	_ "` + modulePath + `/internal/platform/postgres/ledger"
	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5"
)

var (
	_ = g.LedgerCode
	_ = g.StoreDetail
	_ = g.StoreError
	_ = gm.CodeApprovalInvalid
	_ = gm.HoldRefused
	_ = gm.RevealRowsChanged
	_ = gm.DetailAlreadyApproved
	_ = approval.RequestSQL
	_ *action.StoreError
	_ = toolresult.ToolError{SQLState: "57014"}
	_ = map[string]any{"sql": 1}
	_ = "SQL"
	_ = "pg_catalog"

	// Allowed: the approval's own names, and Basalt's cap.
	_ = g.CodeStoreError
	_ = gm.MaxHeldLinesBytes
	_ = approvalstore.ApprovalRevealRefused
	_ *approvalstore.ApprovalRefusalError
	_ = approval.ParseBinding
	_ = "sqlite"
	_ = "the held request"
)

type ref struct{ TableOID uint32 }

func RevealHeld() {}
`,
	})
	findings, files, err := storeNeutralFindings(dir, approvalStoreRule)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("scanned %d files, want 1", files)
	}
	want := []string{
		`a.go: identifier SQLState`,
		`a.go: identifier TableOID`,
		`a.go: import ` + modulePath + `/internal/core/sqlguard`,
		`a.go: import ` + modulePath + `/internal/platform/postgres/ledger`,
		`a.go: import github.com/jackc/pgconn`,
		`a.go: import github.com/jackc/pgx/v5`,
		`a.go: selector action.StoreError`,
		`a.go: selector approval.RequestSQL`,
		`a.go: selector g.LedgerCode`,
		`a.go: selector g.StoreDetail`,
		`a.go: selector g.StoreError`,
		`a.go: selector gm.CodeApprovalInvalid`,
		`a.go: selector gm.DetailAlreadyApproved`,
		`a.go: selector gm.HoldRefused`,
		`a.go: selector gm.RevealRowsChanged`,
		`a.go: text "SQL"`,
		`a.go: text "pg_catalog"`,
		`a.go: text "sql"`,
	}
	if !slices.Equal(findings, want) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(want, "\n"))
	}
	i := slices.IndexFunc(inboundStoreRules(t), func(r storeRule) bool { return filepath.Base(r.dir) == "approvalmcp" })
	if i < 0 {
		t.Fatal("no inbound rule for approvalmcp")
	}
	if mcp := inboundStoreRules(t)[i]; mcp.dir == approvalStoreRule.dir || mcp.text != approvalStoreRule.text || len(mcp.selectors) != len(approvalStoreRule.selectors) {
		t.Errorf("the approval tools' rule is not the approval rule on approvalmcp: %+v", mcp)
	}
}
