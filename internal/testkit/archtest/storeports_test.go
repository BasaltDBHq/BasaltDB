package archtest

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A store-neutral domain's store ports speak its own store types package
// (core/<domain>store, or core/pluginmodel for the plugin host) and the
// ledger types every domain shares (core/action), never another domain's
// store types. storePortTypes finds the exported interface methods of each
// domain root whose signatures name another domain's store types package.

// storeTypesPackages are the store types packages, by the domain root that
// owns each.
var storeTypesPackages = map[string]string{
	"internal/agent":    modulePath + "/internal/core/agentstore",
	"internal/pii":      modulePath + "/internal/core/piistore",
	"internal/approval": modulePath + "/internal/core/approvalstore",
	"internal/revert":   modulePath + "/internal/core/revertstore",
	"internal/plugin":   modulePath + "/internal/core/pluginmodel",
}

// storePortTypes returns one line per domain root, exported interface
// method and foreign store types package its signature names:
// "<domain> <Interface>.<Method>: <package>". The lines carry no file or
// line, so moving a port keeps its line, and each fix removes one.
func storePortTypes(root string) ([]string, error) {
	pkgs, err := load(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for domain, own := range storeTypesPackages {
		pk, ok := pkgs[domain]
		if !ok {
			continue
		}
		for _, f := range pk.files {
			names := localNames(f.ast)
			for _, s := range f.ast.Imports {
				ip := importPath(s)
				if s.Name != nil && s.Name.Name == "." && ip != own && isStoreTypesPackage(ip) {
					out = append(out, domain+" "+f.name+": dot-imports "+strings.TrimPrefix(ip, modulePath+"/"))
				}
			}
			for _, d := range f.ast.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, sp := range gd.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok || !ts.Name.IsExported() {
						continue
					}
					it, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						continue
					}
					for _, m := range it.Methods.List {
						if len(m.Names) == 0 {
							continue // an embedded interface is checked where it is declared
						}
						for _, ip := range foreignStoreTypes(m.Type, names, own) {
							out = append(out, domain+" "+ts.Name.Name+"."+m.Names[0].Name+": "+strings.TrimPrefix(ip, modulePath+"/"))
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// foreignStoreTypes is the store types packages other than own that n
// names, through the file's import names (an alias too).
func foreignStoreTypes(n ast.Node, names map[string]string, own string) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		ip, ok := names[id.Name]
		if ok && ip != own && isStoreTypesPackage(ip) {
			out = append(out, ip)
		}
		return true
	})
	return out
}

// isStoreTypesPackage reports whether ip is one of the store types packages.
func isStoreTypesPackage(ip string) bool {
	for _, p := range storeTypesPackages {
		if p == ip {
			return true
		}
	}
	return false
}

const storePortsBaseline = "storeports_baseline.txt"

// TestStorePortsSpeakOneStoreTypesPackage fails a domain's store port that
// names another domain's store types package and that the baseline does not
// list, and a baseline line that is no longer true. The baseline only
// shrinks: move the type to core/action when every domain shares it, or to
// the domain's own store types package. -update drops the lines no longer
// true and never adds one.
func TestStorePortsSpeakOneStoreTypesPackage(t *testing.T) {
	root := moduleRoot(t)
	got, err := storePortTypes(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "internal", "testkit", "archtest", storePortsBaseline)
	base := readLines(t, file)
	if *update {
		kept := shrinkBaseline(base, got)
		if err := os.WriteFile(file, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, l := range got {
		if !slices.Contains(base, l) {
			t.Errorf("%s\n\ta store port names another domain's store types; use core/action for a shared type "+
				"or the domain's own store types package (do not add it to %s)", l, storePortsBaseline)
		}
	}
	for _, l := range base {
		if !slices.Contains(got, l) {
			t.Errorf("%s\n\tno longer true; remove it from %s", l, storePortsBaseline)
		}
	}
}

// TestStorePortTypesCatchesViolations runs the check on a small module: a
// port naming another domain's store types, through an alias and a dot
// import, is found; its own package, core/action, an unexported interface
// and a test file pass.
func TestStorePortTypesCatchesViolations(t *testing.T) {
	m := modulePath + "/internal/core/"
	root := fixture(t, map[string]string{
		"go.mod": "module " + modulePath + "\n",
		"internal/revert/ports.go": "package revert\n\nimport (\n\t\"" + m + "action\"\n\tas \"" + m + "agentstore\"\n\t\"" + m + "approvalstore\"\n\t\"" + m + "revertstore\"\n)\n\n" +
			"type Records interface {\n\tFind(s revertstore.Scope) (action.Revert, error)\n\tHold(r approvalstore.HoldRequest) []as.FieldRef\n}\n\n" +
			"type quiet interface {\n\tX(approvalstore.Held)\n}\n",
		"internal/revert/dot.go":        "package revert\n\nimport . \"" + m + "piistore\"\n\nvar _ Kind\n",
		"internal/revert/p_test.go":     "package revert\n\nimport \"" + m + "approvalstore\"\n\ntype T interface{ X(approvalstore.Held) }\n",
		"internal/approval/ports.go":    "package approval\n\nimport \"" + m + "approvalstore\"\n\ntype Holds interface {\n\tHold() approvalstore.Held\n}\n",
		"internal/links/ports.go":       "package links\n\nimport \"" + m + "approvalstore\"\n\ntype Reads interface {\n\tFind() approvalstore.Held\n}\n",
		"internal/core/agentstore/a.go": "package agentstore\n\ntype FieldRef string\n",
	})
	got, err := storePortTypes(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/revert Records.Hold: internal/core/agentstore",
		"internal/revert Records.Hold: internal/core/approvalstore",
		"internal/revert dot.go: dot-imports internal/core/piistore",
	}
	if !slices.Equal(got, want) {
		t.Errorf("storePortTypes =\n%q\nwant\n%q", got, want)
	}
}
