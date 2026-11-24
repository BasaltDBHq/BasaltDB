package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuardMigrationHooksStayInTests keeps the hooks that append or trim the
// guard's migrations (guard.AppendTestMigrations, guard.KeepTestMigrationsUpTo,
// guard.TestMigration) out of product code: only the guardtest helper and
// test files may name them, so nothing a user runs can add a migration.
func TestGuardMigrationHooksStayInTests(t *testing.T) {
	root := moduleRoot(t)
	guardDir := filepath.Join("internal", "platform", "postgres", "guard")
	hooks := []string{"AppendTestMigrations", "KeepTestMigrationsUpTo", "guard.TestMigration", "guard/guardtest"}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
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

	// Inside the guard package, only the hook file may reassign migrations.
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
		if strings.Contains(string(b), "\tmigrations = ") {
			t.Errorf("%s assigns migrations: only test_migrations.go may", n)
		}
	}
}
