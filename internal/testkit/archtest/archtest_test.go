package archtest

import (
	"flag"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "remove the baseline lines that are no longer violated (it never adds one)")

// moduleRoot finds the directory with go.mod above the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func baselineFile(dir, pkg string) string {
	return filepath.Join(dir, strings.ReplaceAll(pkg, "/", "_")+".txt")
}

func readLines(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestRegister(t *testing.T) {
	root := moduleRoot(t)
	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range checkRegister(pkgs, reg) {
		t.Error(p)
	}
	for _, p := range checkTestHelpers(pkgs) {
		t.Error(p)
	}
}

// TestArchitecture fails on a violation the baseline does not list and on a
// baseline entry that is no longer violated.
func TestArchitecture(t *testing.T) {
	root := moduleRoot(t)
	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := analyze(root, reg)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "internal", "testkit", "archtest", "baseline")

	if *update {
		for _, l := range shrinkBaselineDir(t, dir, got) {
			t.Errorf("%s\n\tnew violation; fix it (-update only removes baseline lines, it never adds one)", l)
		}
		return
	}

	known := map[string]bool{} // baseline file -> seen among current violators
	for pkg, lines := range got {
		file := baselineFile(dir, pkg)
		known[file] = true
		base := map[string]bool{}
		if _, err := os.Stat(file); err == nil {
			for _, l := range readLines(t, file) {
				base[l] = true
			}
		}
		now := map[string]bool{}
		for _, l := range lines {
			now[l] = true
			if !base[l] {
				t.Errorf("%s: %s\n\tnew violation; fix it (do not add it to the baseline)", pkg, l)
			}
		}
		var stale []string
		for l := range base {
			if !now[l] {
				stale = append(stale, l)
			}
		}
		slices.Sort(stale)
		for _, l := range stale {
			t.Errorf("%s: %s\n\tno longer violated; remove it from %s (or run -update)", pkg, l, filepath.Base(file))
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		file := filepath.Join(dir, e.Name())
		if known[file] || e.IsDir() {
			continue
		}
		for _, l := range readLines(t, file) {
			t.Errorf("%s: %s\n\tno longer violated; remove it (delete the file, or run -update)", e.Name(), l)
		}
	}
}

// fixture writes a small module and returns its root.
// shrinkBaselineDir rewrites the baseline in dir to the lines that are both
// listed and still violated: a fixed violation leaves it, and a new one is
// never added. It returns the violations the baseline does not list, as
// "pkg: line", for the caller to fail on.
func shrinkBaselineDir(t *testing.T, dir string, got violations) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	listed := map[string]bool{} // baseline file -> listed
	for _, e := range entries {
		// .gitkeep keeps the registered directory when every file is gone:
		// scripts/baseline-shrink.sh fails a registered baseline that is gone.
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			listed[filepath.Join(dir, e.Name())] = true
		}
	}
	var refused []string
	for pkg, lines := range got {
		file := baselineFile(dir, pkg)
		base := map[string]bool{}
		if listed[file] {
			for _, l := range readLines(t, file) {
				base[l] = true
			}
		}
		var keep []string
		for _, l := range lines {
			if base[l] {
				keep = append(keep, l)
			} else {
				refused = append(refused, pkg+": "+l)
			}
		}
		if len(keep) == 0 {
			continue
		}
		delete(listed, file)
		if err := os.WriteFile(file, []byte(strings.Join(keep, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for file := range listed {
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(refused)
	return refused
}

// -update removes the fixed lines and files and adds nothing: a new
// violation, in a listed package or a new one, is returned, not written.
func TestShrinkBaselineDirNeverAdds(t *testing.T) {
	dir := fixture(t, map[string]string{
		".gitkeep":       "",
		"internal_a.txt": "fixed\nkept\n",
		"internal_b.txt": "gone\n",
	})
	refused := shrinkBaselineDir(t, dir, violations{
		"internal/a": {"kept", "new in a"},
		"internal/c": {"new in c"},
	})
	if want := []string{"internal/a: new in a", "internal/c: new in c"}; !slices.Equal(refused, want) {
		t.Errorf("refused %q, want %q", refused, want)
	}
	if got := readLines(t, filepath.Join(dir, "internal_a.txt")); !slices.Equal(got, []string{"kept"}) {
		t.Errorf("internal_a.txt = %q, want only the kept line", got)
	}
	for _, gone := range []string{"internal_b.txt", "internal_c.txt"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s exists after -update (err %v); a fixed file is removed and a new one never written", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitkeep")); err != nil {
		t.Errorf(".gitkeep is gone after -update (%v); it keeps the registered directory", err)
	}
}

func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func imp(paths ...string) string {
	var b strings.Builder
	b.WriteString("import (\n")
	for _, p := range paths {
		b.WriteString("\t_ \"" + p + "\"\n")
	}
	b.WriteString(")\n")
	return b.String()
}

// TestRulesCatchViolations runs the checks on a small module with a breach of each rule.
func TestRulesCatchViolations(t *testing.T) {
	m := modulePath + "/"
	guard := "package policy\n\nfunc Check() {}\nfunc Other() {}\nfunc WithRowVersions() {}\ntype Limits struct{}\n"
	use := func(_, fn string) string { return "\nvar _ = policy." + fn + "\n" }
	files := map[string]string{
		"go.mod":                                   "module " + modulePath + "\n",
		"internal/platform/db/db.go":               "package db\n",
		"internal/core/policy/g.go":                guard,
		"internal/core/leaky/l.go":                 "package leaky\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"time\"\n\t. \"strings\"\n\t_ \"github.com/pganalyze/pg_query_go/v6\"\n\t_ \"github.com/wasilibs/go-pgquery\"\n)\n\nvar _ = os.Getenv\nvar _ = syscall.Getpid\nvar Now = time.Now\nvar Since = time.Since\n",
		"internal/core/rnd/r.go":                   "package rnd\n\n" + imp("crypto/rand"),
		"internal/core/granted/r.go":               "package granted\n\n" + imp("crypto/rand"),
		"internal/core/setupcode/a.go":             "package setupcode\n\nimport \"net\"\n\nvar _ = net.JoinHostPort\nvar _ = net.Dial\nvar _ = net.ParseIP\n",
		"internal/core/trustprofile/a.go":          "package trustprofile\n\nimport (\n\t\"io/fs\"\n\t\"net\"\n)\n\nvar _ fs.FS\nvar _ = fs.ReadDir\nvar _ = fs.Glob\nvar _ = net.ParseIP\nvar _ = net.JoinHostPort\n",
		"internal/agent/s.go":                      "package agent\n\n" + imp(m+"internal/platform/db") + "import \"" + m + "internal/core/policy\"\n" + use("", "Check"),
		"internal/agent/in/agentmcp/i.go":          "package agentmcp\n\nimport \"" + m + "internal/core/policy\"\n" + use("", "Check") + "var _ policy.Limits\n",
		"internal/agent/out/other/o.go":            "package other\n\nimport \"" + m + "internal/core/policy\"\n" + use("", "Check") + use("", "Other"),
		"web/w.go":                                 "package web\n\n" + imp(m+"internal/agent") + "import \"" + m + "internal/core/policy\"\n" + use("", "Check") + use("", "Other"),
		"internal/approval/s.go":                   "package approval\n\n" + imp(m+"web"),
		"internal/app/a.go":                        "package app\n\nimport \"" + m + "internal/core/policy\"\n" + use("", "Check"),
		"cmd/tool/c.go":                            "package main\n\nimport \"" + m + "internal/core/policy\"\n" + use("", "Check") + "func main() {}\n",
		"pkg/facade/p.go":                          "package facade\n\nimport \"" + m + "internal/core/policy\"\n" + use("", "Check"),
		"pkg/lib2/p.go":                            "package lib2\n\n" + imp(m+"api/x"),
		"pkg/setup/s.go":                           "package setup\n\n" + imp(m+"internal/setup", m+"internal/platform/postgres/setupstore", m+"internal/platform/db"),
		"pkg/other/o.go":                           "package other\n\n" + imp(m+"internal/platform/db"),
		"api/x/x.go":                               "package x\n",
		"internal/platform/vault/vaulttest/h.go":   "package vaulttest\n\n" + imp(m+"internal/agent"),
		"internal/core/textrule/textruletest/h.go": "package textruletest\n\n" + imp(m+"internal/agent", "os"),
		"internal/testkit/toolschema/t.go":         "package toolschema\n\n" + imp(m+"internal/platform/vault/vaulttest", m+"internal/core/textrule/textruletest"),
		"internal/revert/in/revertmcp/i.go":        "package revertmcp\n\n" + imp(m+"internal/platform/vault/vaulttest"),
		"internal/plugin/out/plugintransport/t.go": "package plugintransport\n\n" + imp(m+"internal/testkit/toolschema"),
		"scripts/smoke/s.go":                       "package main\n\n" + imp(m+"internal/core/textrule/textruletest") + "func main() {}\n",
		"e2e/release/r.go":                         "package release\n\n" + imp(m+"internal/platform/db", m+"internal/platform/vault/vaulttest"),
		"internal/status/s.go":                     "package status\n\n" + imp("github.com/jackc/pgx/v5/pgconn", "database/sql", "net/http", "connectrpc.com/connect", "google.golang.org/grpc", m+"api/connect/proto/basalt/connect/v1/connectv1connect", m+"api/connect/proto/basalt/connect/v1", m+"api/connect"),
		"internal/status/t.go":                     "package status\n\n" + imp("github.com/jackc/pgx/v5", "github.com/jackc/pgx/v5/pgxpool", "net/http/httptest", "net/http/httputil", "net/textproto", "net/url", "google.golang.org/grpc/credentials", "connectrpc.com/grpcreflect", m+"api/plugin/proto/basalt/plugin/v1/pluginv1connect", "google.golang.org/protobuf/proto"),
		"internal/status/s_test.go":                "package status\n\n" + imp("github.com/jackc/pgx/v5"),
		"internal/status/out/pgadapter/p.go":       "package pgadapter\n\n" + imp("github.com/jackc/pgx/v5"),
		"internal/oddball/o.go":                    "package oddball\n",
		"internal/core/textrule/t.go":              "package textrule\n",
		"internal/agent/loadtest/l.go":             "package loadtest\n\n" + imp(m+"internal/platform/db"),
		"internal/core/fake/faketest/f.go":         "package faketest\n\n" + imp("os"),
		"internal/core/leakytest/l.go":             "package leakytest\n\n" + imp("os"),
		"cmd/loadtest/main.go":                     "package main\n\n" + imp(m+"internal/platform/db") + "func main() {}\n",
		"internal/agent/agenttest/main.go":         "package main\n\n" + imp(m+"internal/platform/db") + "func main() {}\n",
		"internal/platform/vault/v.go":             "package vault\n",
		"internal/approval/a.go":                   "package approval\n\n" + imp(m+"internal/agent/loadtest"),
		"ARCHITECTURE.md":                          "| `leakytest` | x | types | 2 | - | - |\n| `policy` | sql | decision | 1 | - | `Other` |\n| `leaky` | x | types | 2 | - | - |\n| `rnd` | x | codec | 3 | `crypto/rand` | - |\n| `granted` | x | codec | 3 | - | - |\n| `setupcode` | x | codec | 3 | `net` | - |\n| `trustprofile` | x | types | 2 | `io/fs`, `net` | - |\n| `textrule` | x | types | 2 | - | - |\n",
	}
	root := fixture(t, files)
	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := analyze(root, reg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"internal/agent":                      {"imports internal/platform/db"},
		"internal/agent/in/agentmcp":          {"i.go calls policy.Check"},
		"internal/revert/in/revertmcp":        {"imports internal/platform/vault/vaulttest (a test helper: only test files import it)"},
		"internal/agent/out/other":            {"o.go calls policy.Check"},
		"internal/plugin/out/plugintransport": {"imports internal/testkit/toolschema (a test helper: only test files import it)"},
		"e2e/release":                         {"imports internal/platform/vault/vaulttest (a test helper: only test files import it)"},
		"web":                                 {"imports internal/agent", "w.go calls policy.Check"},
		"cmd/tool":                            {"c.go calls policy.Check"},
		"pkg/facade":                          {"imports internal/core/policy", "p.go calls policy.Check"},
		"pkg/lib2":                            {"imports api/x"},
		"pkg/other":                           {"imports internal/platform/db"},
		// pkg/setup imports only its allowlist beyond its layer: the setup
		// service and adapter pass, another outbound package does not.
		"pkg/setup": {"imports internal/platform/db"},
		"internal/status": {
			"s.go imports connectrpc.com/connect (a service reaches the database and the network through a port)",
			"s.go imports database/sql (a service reaches the database and the network through a port)",
			"s.go imports github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect (a service reaches the database and the network through a port)",
			"s.go imports github.com/jackc/pgx/v5/pgconn (a service reaches the database and the network through a port)",
			"s.go imports google.golang.org/grpc (a service reaches the database and the network through a port)",
			"s.go imports net/http (a service reaches the database and the network through a port)",
			"t.go imports connectrpc.com/grpcreflect (a service reaches the database and the network through a port)",
			"t.go imports github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect (a service reaches the database and the network through a port)",
			"t.go imports github.com/jackc/pgx/v5 (a service reaches the database and the network through a port)",
			"t.go imports github.com/jackc/pgx/v5/pgxpool (a service reaches the database and the network through a port)",
			"t.go imports google.golang.org/grpc/credentials (a service reaches the database and the network through a port)",
			"t.go imports net/http/httptest (a service reaches the database and the network through a port)",
			"t.go imports net/http/httputil (a service reaches the database and the network through a port)",
		},
		"internal/oddball":            {"package is under internal/ but not in a layer"},
		"internal/agent/loadtest":     {"imports internal/platform/db"},
		"internal/core/fake/faketest": {"f.go imports os (core must stay pure)"},
		"internal/core/leakytest":     {"l.go imports os (core must stay pure)"},
		"cmd/loadtest":                {"imports internal/platform/db"},
		"internal/agent/agenttest":    {"imports internal/platform/db"},
		"internal/core/granted":       {"r.go imports crypto/rand (core must stay pure)"},
		"internal/core/setupcode": {
			"a.go uses net.Dial (the register grants net for JoinHostPort only)",
			"a.go uses net.ParseIP (the register grants net for JoinHostPort only)",
		},
		"internal/core/trustprofile": {
			"a.go uses io/fs.Glob (the register grants io/fs for FS, ReadDir, ReadFile only)",
			"a.go uses net.JoinHostPort (the register grants net for ParseIP only)",
		},
		"internal/core/leaky": {
			"l.go calls time.Now (core must stay pure)",
			"l.go calls time.Since (core must stay pure)",
			"l.go dot-imports strings (not allowed in core)",
			"l.go imports github.com/pganalyze/pg_query_go/v6 (core must stay pure)",
			"l.go imports github.com/wasilibs/go-pgquery (core must stay pure)",
			"l.go imports os (core must stay pure)",
			"l.go imports syscall (core must stay pure)",
		},
	}
	for pkg, lines := range want {
		if strings.Join(got[pkg], "|") != strings.Join(lines, "|") {
			t.Errorf("%s: got %q, want %q", pkg, got[pkg], lines)
		}
	}
	for pkg := range got {
		if _, ok := want[pkg]; !ok {
			t.Errorf("unexpected violations in %s: %q", pkg, got[pkg])
		}
	}
}

func TestRegisterChecksCatchProblems(t *testing.T) {
	root := fixture(t, map[string]string{
		"go.mod":                     "module " + modulePath + "\n",
		"internal/core/noRow/a.go":   "package noRow\n",
		"internal/core/badkind/a.go": "package badkind\n",
		"internal/core/badrow/a.go":  "package badrow\n",
		"internal/core/extra/a.go":   "package extra\n",
		"internal/core/chan/a.go":    "package channel\n",
		"internal/core/dec/a.go":     "package dec\n\nfunc Real() {}\n",
		"ARCHITECTURE.md":            "| `badkind` | x | gadget | 1 | - | - |\n| `badrow` | x | types | 4 | - | `Zed` |\n| `extra` | x | codec | 3 | `crypto/rand`, `net`, `io/fs` | - |\n| `dec` | x | decision | 1 | - | `Real`, `Missing` |\n| `chan` | x | codec | 3 | `os` | `Nope` |\n| `ghost` | x | types | 2 | - | - |\n",
	})
	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(checkRegister(pkgs, reg), "\n")
	for _, w := range []string{
		"internal/core/noRow is not in the core register",
		"lists ghost but internal/core/ghost does not exist",
		`register row badkind: kind "gadget"`,
		`register row badrow: admitted-by "4"`,
		`register row extra: extra import "crypto/rand" is not allowed`,
		`register row extra: extra import "net" is not allowed`,
		`register row extra: extra import "io/fs" is not allowed`,
		`register row chan: extra import "os" is not allowed`,
		`register row dec: codec function "Missing" is not an exported function`,
		`register row chan: codec function "Nope" is not an exported function`,
		`register row badrow: codec functions are listed only for a decision package`,
	} {
		if !strings.Contains(all, w) {
			t.Errorf("checkRegister did not report %q; got:\n%s", w, all)
		}
	}
}

// TestNewTreeLayers checks the layer table of the new tree (domain folders):
// platform transports are inbound, the rest of platform outbound, a domain's
// in/ and out/ are inbound and outbound and its root is a service; the
// Postgres store, like any adapter, calls no core decision, the plugin path
// rule keeps its owner at the new paths, and the moved test helpers stay
// exempt.
func TestNewTreeLayers(t *testing.T) {
	m := modulePath + "/"
	guard := "package policy\n\nfunc Check() {}\nfunc Other() {}\nfunc WithRowVersions() {}\n"
	use := func(fn string) string { return "\nvar _ = policy." + fn + "\n" }
	sg := "import \"" + m + "internal/core/policy\"\n"
	files := map[string]string{
		"go.mod":                                 "module " + modulePath + "\n",
		"internal/core/policy/g.go":              guard,
		"internal/platform/postgres/store/s.go":  "package store\n\n" + sg + use("Check") + use("WithRowVersions"),
		"internal/platform/postgres/other/o.go":  "package other\n\n" + sg + use("Check"),
		"internal/platform/mcpserver/m.go":       "package mcpserver\n\n" + imp(m+"internal/setup"),
		"internal/platform/vault/v.go":           "package vault\n\n" + imp(m+"internal/setup"),
		"internal/platform/vault/vaulttest/h.go": "package vaulttest\n\n" + imp(m+"internal/setup"),
		"internal/setup/s.go":                    "package setup\n\n" + imp("net/http", m+"internal/platform/vault"),
		"internal/setup/in/setupcli/c.go":        "package setupcli\n\n" + imp(m+"internal/setup", m+"internal/platform/mcpserver"),
		"internal/setup/out/trustdir/t.go":       "package trustdir\n\n" + imp(m+"internal/setup"),
		"internal/plugin/p.go":                   "package plugin\n\nfunc UsePathRules() {}\n",
		"internal/platform/osservice/o.go":       "package osservice\n\nimport \"" + m + "internal/plugin\"\n\nfunc init() { plugin.UsePathRules() }\n",
		"internal/app/a.go":                      "package app\n\nimport \"" + m + "internal/plugin\"\n\nfunc init() { plugin.UsePathRules() }\n",
		"internal/zzz/z.go":                      "package zzz\n",
		"ARCHITECTURE.md":                        "| `policy` | sql | decision | 1 | - | `Other` |\n",
	}
	root := fixture(t, files)
	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := analyze(root, reg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"internal/platform/postgres/other": {"o.go calls policy.Check"},
		"internal/platform/postgres/store": {"s.go calls policy.Check", "s.go calls policy.WithRowVersions"},
		"internal/platform/vault":          {"imports internal/setup"},
		"internal/platform/mcpserver":      {"imports internal/setup (an internal/platform package imports no domain service)"},
		"internal/setup": {
			"imports internal/platform/vault",
			"s.go imports net/http (a service reaches the database and the network through a port)",
		},
		"internal/setup/out/trustdir": {"imports internal/setup"},
		"internal/platform/osservice": {"imports internal/plugin", "o.go calls plugin.UsePathRules (only internal/app installs the path rule)"},
		"internal/zzz":                {"package is under internal/ but not in a layer"},
	}
	for pkg, lines := range want {
		if strings.Join(got[pkg], "|") != strings.Join(lines, "|") {
			t.Errorf("%s: got %q, want %q", pkg, got[pkg], lines)
		}
	}
	for pkg := range got {
		if _, ok := want[pkg]; !ok {
			t.Errorf("unexpected violations in %s: %q", pkg, got[pkg])
		}
	}
}

// wherePaths are the files and directories, from the module root, that the
// "Where is a feature" section of the architecture doc at file names. A cell names
// a path from the root, and may name more files after it by their name or a
// path relative to that path's directory: `a/b/x.go`, `y.go`,
// `schema/z.sql`. Backticked text that is not a path (a tool name) is left
// out.
func wherePaths(t *testing.T, file string) []string {
	t.Helper()
	var out []string
	in := false
	for _, line := range readLines(t, file) {
		if strings.HasPrefix(line, "## ") {
			in = line == "## Where is a feature"
			continue
		}
		if !in || !strings.HasPrefix(line, "|") {
			continue
		}
		for _, cell := range strings.Split(line, "|") {
			dir := ""
			for _, m := range backticked.FindAllStringSubmatch(cell, -1) {
				p := m[1]
				switch {
				case strings.HasPrefix(p, "internal/"), strings.HasPrefix(p, "pkg/"), strings.HasPrefix(p, "cmd/"), strings.HasPrefix(p, "web/"), strings.HasPrefix(p, "api/"):
					dir = p
					if path.Ext(p) != "" {
						dir = path.Dir(p)
					}
				case sourceFile.MatchString(p) && dir != "":
					p = path.Join(dir, p)
				default:
					continue
				}
				out = append(out, p)
			}
		}
	}
	return out
}

var (
	backticked = regexp.MustCompile("`([^`]+)`")
	sourceFile = regexp.MustCompile(`^[\w./-]+\.(go|sql|js|json)$`)
)

// Every path the "Where is a feature" section names exists.
func TestWhereIsAFeaturePathsExist(t *testing.T) {
	root := moduleRoot(t)
	paths := wherePaths(t, filepath.Join(root, "ARCHITECTURE.md"))
	if len(paths) == 0 {
		t.Fatal(`ARCHITECTURE.md's "Where is a feature" names no path: the check reads nothing`)
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			t.Errorf(`ARCHITECTURE.md, "Where is a feature": %s does not exist; point the row at where the code is now`, p)
		}
	}
}

// The path reader resolves a name after a path against that path's
// directory, and skips what is not a path.
func TestWherePathsReadsTheCells(t *testing.T) {
	dir := fixture(t, map[string]string{
		"ARCHITECTURE.md": "## Before\n\n| x | `internal/before.go` |\n\n## Where is a feature\n\n### Reverts\n\n" +
			"| Step | Where |\n|---|---|\n" +
			"| Tool `request_revert` | `internal/revert/in/revertmcp/tools.go`; the case in `internal/revert/service.go`, `rescope.go` |\n" +
			"| SQL | `internal/platform/postgres/guard`, `schema/006_reverts.sql` |\n" +
			"| Alone | `orphan.go` |\n\n## After\n\n| y | `internal/after.go` |\n",
	})
	got := wherePaths(t, filepath.Join(dir, "ARCHITECTURE.md"))
	want := []string{
		"internal/revert/in/revertmcp/tools.go",
		"internal/revert/service.go",
		"internal/revert/rescope.go",
		"internal/platform/postgres/guard",
		"internal/platform/postgres/guard/schema/006_reverts.sql",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
