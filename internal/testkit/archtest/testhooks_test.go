package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGuardMigrationHooksStayInTests(t *testing.T) {
	root := moduleRoot(t)
	guardDir := filepath.Join("internal", "platform", "postgres", "guard")
	hooks := []string{"AppendTestMigrations", "KeepTestMigrationsUpTo", "guard.TestMigration", "guard/guardtest"}
	for _, top := range []string{"internal", "cmd", "pkg"} {
		if _, err := os.Stat(filepath.Join(root, top)); err != nil {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if strings.HasPrefix(rel, filepath.Join(guardDir, "guardtest")+string(filepath.Separator)) ||
				rel == filepath.Join(guardDir, "test_migrations.go") ||
				strings.HasPrefix(rel, filepath.Join("internal", "testkit")+string(filepath.Separator)) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, h := range hooks {
				if strings.Contains(string(b), h) {
					t.Errorf("%s names %q: the migration test hooks are for tests only", rel, h)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	assignsMigrations := regexp.MustCompile(`(?m)^[ \t]*migrations\s*(=|,)`)
	entries, err := os.ReadDir(filepath.Join(root, guardDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "test_migrations.go" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, guardDir, n))
		if err != nil {
			t.Fatal(err)
		}
		if assignsMigrations.Match(b) {
			t.Errorf("%s assigns migrations: only test_migrations.go may", n)
		}
	}
}
