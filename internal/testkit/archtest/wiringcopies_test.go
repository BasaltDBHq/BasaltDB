package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// wiringCopy matches a test's own copy of what the engine wires: the agent's
// error map over the Postgres adapters' errors (pgerrors.Map) or the host's
// service manager (osservice.Manager). A test calls those instead, so it
// never runs on a copy production no longer uses.
var wiringCopy = regexp.MustCompile(`(?m)^func (testErrors|testErrorMap|testManager)\(\)|InvalidParams:\s*ledger\.ErrInvalidParams|StartCommand:\s*osservice\.StartCommand`)

// wiringCopies returns, for the Go files under root/internal, cmd and pkg,
// one "<file>: <match>" line per copy outside the two homes.
func wiringCopies(root string) ([]string, error) {
	homes := map[string]bool{
		filepath.Join("internal", "platform", "postgres", "pgerrors", "pgerrors.go"): true,
		filepath.Join("internal", "platform", "osservice", "manager.go"):             true,
	}
	var out []string
	for _, top := range []string{"internal", "cmd", "pkg"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if homes[rel] || strings.HasPrefix(rel, filepath.Join("internal", "testkit", "archtest")+string(filepath.Separator)) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range wiringCopy.FindAllString(string(b), -1) {
				out = append(out, filepath.ToSlash(rel)+": "+m)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func TestNoCopyOfTheWiredErrorsOrServiceManager(t *testing.T) {
	got, err := wiringCopies(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		t.Errorf("%s\n\tuse pgerrors.Map() or osservice.Manager(), the copies the engine wires", l)
	}
}

func TestWiringCopiesCatchesViolations(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/x/h_test.go", "package x\n\nfunc testErrors() guidance.ErrorMap {\n\treturn guidance.ErrorMap{InvalidParams: ledger.ErrInvalidParams}\n}\n")
	write("internal/y/m_test.go", "package y\n\nvar m = guidance.ServiceManager{StartCommand: osservice.StartCommand}\n")
	write("internal/platform/postgres/pgerrors/pgerrors.go", "package pgerrors\n\nvar m = guidance.ErrorMap{InvalidParams: ledger.ErrInvalidParams}\n")
	write("internal/z/fake_test.go", "package z\n\nvar m = guidance.ErrorMap{InvalidParams: errFake}\n")
	got, err := wiringCopies(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/x/h_test.go: func testErrors()",
		"internal/x/h_test.go: InvalidParams: ledger.ErrInvalidParams",
		"internal/y/m_test.go: StartCommand: osservice.StartCommand",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("wiringCopies = %q, want %q", got, want)
	}
}
