package archtest

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite baseline/ to match the violations that exist now")

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
		sort.Strings(stale)
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

// TestRulesCatchViolations runs the checks on a small module with one breach of each rule.
func TestRulesCatchViolations(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := modulePath
	write("go.mod", "module "+m+"\n")
	write("internal/adapter/outbound/db/db.go", "package db\n")
	write("internal/core/sqlguard/g.go", "package sqlguard\n\nfunc Check() {}\n\ntype Limits struct{}\n")
	write("internal/core/leaky/l.go", "package leaky\n\nimport (\n\t\"os\"\n\t\"time\"\n)\n\nvar _ = os.Getenv\nvar Now = time.Now\n")
	write("internal/core/rnd/r.go", "package rnd\n\nimport _ \"crypto/rand\"\n")
	write("internal/service/svc/s.go", "package svc\n\nimport (\n\t_ \""+m+"/internal/adapter/outbound/db\"\n\t\""+m+"/internal/core/sqlguard\"\n)\n\nvar _ = sqlguard.Check\n")
	write("internal/adapter/inbound/in/i.go", "package in\n\nimport \""+m+"/internal/core/sqlguard\"\n\nvar _ = sqlguard.Check\nvar _ sqlguard.Limits\n")
	write("internal/adapter/outbound/postgres/store/s.go", "package store\n\nimport \""+m+"/internal/core/sqlguard\"\n\nvar _ = sqlguard.Check\n")
	write("internal/oddball/o.go", "package oddball\n")
	write("ARCHITECTURE.md", "| `sqlguard` | sql | decision | 1 | - |\n| `leaky` | x | types | 2 | - |\n| `rnd` | x | codec | 3 | `crypto/rand` |\n")

	reg, err := parseRegister(filepath.Join(root, "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := analyze(root, reg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"internal/service/svc":        {"imports internal/adapter/outbound/db"},
		"internal/adapter/inbound/in": {"i.go calls sqlguard.Check"},
		"internal/oddball":            {"package is under internal/ but not in a layer"},
		"internal/core/leaky":         {"l.go calls time.Now (core must stay pure)", "l.go imports os (core must stay pure)"},
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
