package archtest

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the baselines: baseline/ to match the violations that exist now; the service I/O baseline only drops lines no longer true")

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
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			return
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for pkg, lines := range got {
			if err := os.WriteFile(baselineFile(dir, pkg), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
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
	guard := "package sqlguard\n\nfunc Check() {}\nfunc Other() {}\nfunc WithRowVersions() {}\ntype Limits struct{}\n"
	use := func(_, fn string) string { return "\nvar _ = sqlguard." + fn + "\n" }
	files := map[string]string{
		"go.mod":                                   "module " + modulePath + "\n",
		"internal/adapter/outbound/db/db.go":       "package db\n",
		"internal/core/sqlguard/g.go":              guard,
		"internal/core/leaky/l.go":                 "package leaky\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"time\"\n\t. \"strings\"\n)\n\nvar _ = os.Getenv\nvar _ = syscall.Getpid\nvar Now = time.Now\nvar Since = time.Since\n",
		"internal/core/rnd/r.go":                   "package rnd\n\n" + imp("crypto/rand"),
		"internal/core/granted/r.go":               "package granted\n\n" + imp("crypto/rand"),
		"internal/core/setupcode/a.go":             "package setupcode\n\nimport \"net\"\n\nvar _ = net.JoinHostPort\nvar _ = net.Dial\n",
		"internal/service/svc/s.go":                "package svc\n\n" + imp(m+"internal/adapter/outbound/db") + "import \"" + m + "internal/core/sqlguard\"\n" + use("", "Check"),
		"internal/adapter/inbound/in/i.go":         "package in\n\nimport \"" + m + "internal/core/sqlguard\"\n" + use("", "Check") + "var _ sqlguard.Limits\n",
		"internal/adapter/outbound/other/o.go":     "package other\n\nimport \"" + m + "internal/core/sqlguard\"\n" + use("", "Check") + use("", "Other"),
		"web/w.go":                                 "package web\n\n" + imp(m+"internal/service/svc") + "import \"" + m + "internal/core/sqlguard\"\n" + use("", "Check") + use("", "Other"),
		"internal/service/svc2/s.go":               "package svc2\n\n" + imp(m+"web"),
		"internal/app/a.go":                        "package app\n\nimport \"" + m + "internal/core/sqlguard\"\n" + use("", "Check"),
		"cmd/tool/c.go":                            "package main\n\nimport \"" + m + "internal/core/sqlguard\"\n" + use("", "Check") + "func main() {}\n",
		"pkg/facade/p.go":                          "package facade\n\nimport \"" + m + "internal/core/sqlguard\"\n" + use("", "Check"),
		"pkg/lib2/p.go":                            "package lib2\n\n" + imp(m+"api/x"),
		"pkg/setup/s.go":                           "package setup\n\n" + imp(m+"internal/adapter/outbound/db"),
		"pkg/other/o.go":                           "package other\n\n" + imp(m+"internal/adapter/outbound/db"),
		"api/x/x.go":                               "package x\n",
		"internal/platform/vault/vaulttest/h.go":   "package vaulttest\n\n" + imp(m+"internal/service/svc"),
		"internal/adapter/inbound/in2/i.go":        "package in2\n\n" + imp(m+"internal/platform/vault/vaulttest"),
		"internal/service/svcpg/s.go":              "package svcpg\n\n" + imp("github.com/jackc/pgx/v5/pgconn", "database/sql", "net/http"),
		"internal/service/svcpg/s_test.go":         "package svcpg\n\n" + imp("github.com/jackc/pgx/v5"),
		"internal/adapter/outbound/pgadapter/p.go": "package pgadapter\n\n" + imp("github.com/jackc/pgx/v5"),
		"internal/oddball/o.go":                    "package oddball\n",
		"ARCHITECTURE.md":                          "| `sqlguard` | sql | decision | 1 | - | `Other` |\n| `leaky` | x | types | 2 | - | - |\n| `rnd` | x | codec | 3 | `crypto/rand` | - |\n| `granted` | x | codec | 3 | - | - |\n| `setupcode` | x | codec | 3 | `net` | - |\n",
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
		"internal/service/svc":            {"imports internal/adapter/outbound/db"},
		"internal/adapter/inbound/in":     {"i.go calls sqlguard.Check"},
		"internal/adapter/inbound/in2":    {"imports internal/platform/vault/vaulttest"},
		"internal/adapter/outbound/other": {"o.go calls sqlguard.Check"},
		"web":                             {"imports internal/service/svc", "w.go calls sqlguard.Check"},
		"cmd/tool":                        {"c.go calls sqlguard.Check"},
		"pkg/facade":                      {"imports internal/core/sqlguard", "p.go calls sqlguard.Check"},
		"pkg/lib2":                        {"imports api/x"},
		"pkg/other":                       {"imports internal/adapter/outbound/db"},
		"internal/service/svcpg": {
			"s.go imports database/sql (a service reaches the database and the network through a port)",
			"s.go imports github.com/jackc/pgx/v5/pgconn (a service reaches the database and the network through a port)",
			"s.go imports net/http (a service reaches the database and the network through a port)",
		},
		"internal/oddball":        {"package is under internal/ but not in a layer"},
		"internal/core/granted":   {"r.go imports crypto/rand (core must stay pure)"},
		"internal/core/setupcode": {"a.go uses net.Dial (the register grants net for JoinHostPort only)"},
		"internal/core/leaky": {
			"l.go calls time.Now (core must stay pure)",
			"l.go calls time.Since (core must stay pure)",
			"l.go dot-imports strings (not allowed in core)",
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
		"ARCHITECTURE.md":            "| `badkind` | x | gadget | 1 | - | - |\n| `badrow` | x | types | 4 | - | `Zed` |\n| `extra` | x | codec | 3 | `crypto/rand`, `net` | - |\n| `dec` | x | decision | 1 | - | `Real`, `Missing` |\n| `chan` | x | codec | 3 | `os` | `Nope` |\n| `ghost` | x | types | 2 | - | - |\n",
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
// in/ and out/ are inbound and outbound and its root is a service; the store
// keeps its sqlguard exception and the plugin path rule its owner at the new
// paths, and the moved test helpers stay exempt.
func TestNewTreeLayers(t *testing.T) {
	m := modulePath + "/"
	guard := "package sqlguard\n\nfunc Check() {}\nfunc Other() {}\nfunc WithRowVersions() {}\n"
	use := func(fn string) string { return "\nvar _ = sqlguard." + fn + "\n" }
	sg := "import \"" + m + "internal/core/sqlguard\"\n"
	files := map[string]string{
		"go.mod":                                 "module " + modulePath + "\n",
		"internal/core/sqlguard/g.go":            guard,
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
		"ARCHITECTURE.md":                        "| `sqlguard` | sql | decision | 1 | - | `Other` |\n",
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
		"internal/platform/postgres/other": {"o.go calls sqlguard.Check"},
		"internal/platform/vault":          {"imports internal/setup"},
		"internal/platform/mcpserver":      {"imports internal/setup (an internal/platform package imports no domain service)"},
		"internal/setup": {
			"imports internal/platform/vault",
			"s.go imports net/http (a service reaches the database and the network through a port)",
		},
		"internal/setup/out/trustdir": {"imports internal/setup"},
		"internal/platform/osservice": {"imports internal/plugin", "o.go calls pluginhost.UsePathRules (only internal/app installs the path rule)"},
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
