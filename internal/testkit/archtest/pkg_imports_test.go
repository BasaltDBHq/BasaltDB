package archtest

import (
	"go/ast"
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

// TestPkgForwardsAreListed fails on a pkgForwards edge the package no
// longer imports: a new edge already fails the layer rules.
func TestPkgForwardsAreListed(t *testing.T) {
	_, pkgs := loadModule(t)
	for _, l := range staleImportsAllowlist(pkgs, pkgForwards) {
		t.Errorf("pkgForwards: %s\n\tno longer imported; remove the edge", l)
	}
}

// The forward edges on a probe: a listed edge passes the layer rules, an
// unlisted core import from pkg/ fails, and a listed edge that is gone is
// stale.
func TestPkgForwardsCatchNewAndStaleEdges(t *testing.T) {
	v := violations{}
	checkLayer(v, "pkg/trustpin", lPkg, "internal/core/trustpin")
	checkLayer(v, "pkg/trustpin", lPkg, "internal/core/trustprofile")
	checkLayer(v, "pkg/setup", lPkg, "internal/core/trustpin")
	v.normalize()
	want := map[string][]string{
		"pkg/trustpin": {"imports internal/core/trustprofile"},
		"pkg/setup":    {"imports internal/core/trustpin"},
	}
	for pkg, lines := range want {
		if !slices.Equal(v[pkg], lines) {
			t.Errorf("%s: got %q, want %q", pkg, v[pkg], lines)
		}
	}
	if len(v) != len(want) {
		t.Errorf("violations: got %q", v)
	}
	pkgs := parsePkgs(t, map[string]string{"pkg/trustpin/p.go": "package trustpin\n"})
	got := staleImportsAllowlist(pkgs, map[string][]string{"pkg/trustpin": {"internal/core/trustpin"}})
	if want := []string{"pkg/trustpin: internal/core/trustpin"}; !slices.Equal(got, want) {
		t.Errorf("stale forwards = %q, want %q", got, want)
	}
}

// staleDecisionForwards returns the pkgDecisionForwards entries of allow
// the package no longer calls, as "<package>: <decision>.<function>".
func staleDecisionForwards(pkgs map[string]*goPkg, allow map[string]map[string][]string) []string {
	var out []string
	for rel, decs := range allow {
		called := map[string]bool{}
		if pk := pkgs[rel]; pk != nil {
			for _, f := range pk.files {
				names := localNames(f.ast)
				ast.Inspect(f.ast, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok {
							called[strings.TrimPrefix(names[id.Name], modulePath+"/internal/core/")+"."+sel.Sel.Name] = true
						}
					}
					return true
				})
			}
		}
		for dec, fns := range decs {
			for _, fn := range fns {
				if !called[dec+"."+fn] {
					out = append(out, rel+": "+dec+"."+fn)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// TestPkgDecisionForwardsAreListed fails on a pkgDecisionForwards entry the
// package no longer calls: a new call already fails the decision rule.
func TestPkgDecisionForwardsAreListed(t *testing.T) {
	_, pkgs := loadModule(t)
	for _, l := range staleDecisionForwards(pkgs, pkgDecisionForwards) {
		t.Errorf("pkgDecisionForwards: %s\n\tno longer called; remove it", l)
	}
}

// The decision forwards on a probe: pkg/trustpin may call the listed
// decision functions and the codecs, but no other decision function, and
// no other package under pkg/ may call one.
func TestPkgDecisionForwardsCatchOtherCalls(t *testing.T) {
	m := modulePath + "/"
	src := func(pkg string, calls ...string) string {
		s := "package " + pkg + "\n\nimport \"" + m + "internal/core/trustpin\"\n\n"
		for _, c := range calls {
			s += "var _ = trustpin." + c + "\n"
		}
		return s
	}
	pkgs := parsePkgs(t, map[string]string{
		"pkg/trustpin/p.go":  src("trustpin", "Check", "Approved", "Name", "Other"),
		"pkg/facade2/p.go":   src("facade2", "Check"),
		"pkg/trustpin2/p.go": src("trustpin2", "Approved"),
	})
	decisions := map[string][]string{"trustpin": {"Check", "Approved", "Other"}}
	v := violations{}
	for rel, pk := range pkgs {
		for _, f := range pk.files {
			checkDecisionCalls(v, rel, f, decisions)
		}
	}
	v.normalize()
	want := map[string][]string{
		"pkg/trustpin":  {"p.go calls trustpin.Other"},
		"pkg/facade2":   {"p.go calls trustpin.Check"},
		"pkg/trustpin2": {"p.go calls trustpin.Approved"},
	}
	for pkg, lines := range want {
		if !slices.Equal(v[pkg], lines) {
			t.Errorf("%s: got %q, want %q", pkg, v[pkg], lines)
		}
	}
	if len(v) != len(want) {
		t.Errorf("violations: got %q", v)
	}
	got := staleDecisionForwards(pkgs, map[string]map[string][]string{"pkg/trustpin": {"trustpin": {"Check", "Gone"}}})
	if want := []string{"pkg/trustpin: trustpin.Gone"}; !slices.Equal(got, want) {
		t.Errorf("stale decision forwards = %q, want %q", got, want)
	}
}
