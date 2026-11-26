package archtest

import (
	"slices"
	"strings"
	"testing"
)

// staleImportsAllowlist returns the lines of allow (package to imports) the
// code no longer needs: an import the package does not make, or one its
// layer's list already allows.
func staleImportsAllowlist(pkgs map[string]*goPkg, allow map[string][]string) []string {
	var out []string
	for rel, targets := range allow {
		imported := map[string]bool{}
		if pk := pkgs[rel]; pk != nil {
			for _, f := range pk.files {
				for _, s := range f.ast.Imports {
					imported[strings.TrimPrefix(importPath(s), modulePath+"/")] = true
				}
			}
		}
		for _, target := range targets {
			if !imported[target] || in(allowed[layerOf(rel)], layerOf(target)) {
				out = append(out, rel+": "+target)
			}
		}
	}
	slices.Sort(out)
	return out
}

// TestPkgImportsAllowlistOnlyShrinks fails on a line of
// pkg_imports_allowlist.txt that the code no longer needs: the list names
// exactly what pkg/ imports beyond its layer, so a forward that leaves
// takes its line with it.
func TestPkgImportsAllowlistOnlyShrinks(t *testing.T) {
	for _, p := range pkgExtraProblems {
		t.Errorf("pkg_imports_allowlist.txt: %s\n\teach line is \"pkg/<package>: <import>\"", p)
	}
	_, pkgs := loadModule(t)
	for _, l := range staleImportsAllowlist(pkgs, pkgExtra) {
		t.Errorf("pkg_imports_allowlist.txt: %s\n\tno longer imported beyond the layer; remove the line", l)
	}
}

// The stale-line check on a probe: an import the package dropped, and one
// its layer already allows, are stale; one it makes beyond its layer is not.
func TestPkgImportsAllowlistCatchesAStaleLine(t *testing.T) {
	m := modulePath + "/"
	pkgs := parsePkgs(t, map[string]string{
		"pkg/setup/s.go": "package setup\n\nimport (\n\t_ \"" + m + "internal/setup\"\n\t_ \"" + m + "internal/lib/x\"\n)\n",
	})
	got := staleImportsAllowlist(pkgs, map[string][]string{"pkg/setup": {"internal/setup", "internal/handoff", "internal/lib/x"}})
	want := []string{"pkg/setup: internal/handoff", "pkg/setup: internal/lib/x"}
	if !slices.Equal(got, want) {
		t.Fatalf("stale = %q, want %q", got, want)
	}
}

func TestPkgImportsAllowlistRefusesABadLine(t *testing.T) {
	allow, problems := parsePkgImports("pkg/setup: internal/setup\n\n  \nno separator here\ninternal/app: internal/setup\npkg/setup: \npkg/setup: internal/handoff\n")
	want := map[string][]string{"pkg/setup": {"internal/setup", "internal/handoff"}}
	if len(allow) != len(want) || !slices.Equal(allow["pkg/setup"], want["pkg/setup"]) {
		t.Errorf("allow = %q, want %q", allow, want)
	}
	wantProblems := []string{
		`line 4: "no separator here" is not "<package>: <import>"`,
		`line 5: "internal/app: internal/setup" names internal/app, which is not under pkg/`,
		`line 6: "pkg/setup:" is not "<package>: <import>"`,
	}
	if !slices.Equal(problems, wantProblems) {
		t.Errorf("problems = %q, want %q", problems, wantProblems)
	}
}
