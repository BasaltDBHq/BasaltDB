package guard

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// releasedList names the guard migrations a release has shipped, with
// their sha256. Lines are added only when a release ships.
const releasedList = "schema/released.sha256"

// releasedFloor is the newest migration a release has shipped
// (v0.1.0-alpha): every migration up to it must stay listed, so the list
// only grows. Raise it with the lines a new release adds.
const releasedFloor = 26

// releasedMigrationProblems reads list (sha256 and file name per line, #
// comments) and names every listed file in dir that is gone or whose
// content changed, every malformed or repeated line, and every migration
// number from 1 to floor the list does not name.
func releasedMigrationProblems(dir, list string, floor int) ([]string, int, error) {
	raw, err := os.ReadFile(list)
	if err != nil {
		return nil, 0, err
	}
	var problems []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 || filepath.Base(fields[1]) != fields[1] {
			problems = append(problems, fmt.Sprintf("line %d: want \"<sha256>  <file>.sql\", got %q", n, line))
			continue
		}
		want, name := fields[0], fields[1]
		if seen[name] {
			problems = append(problems, fmt.Sprintf("line %d: %s is listed twice", n, name))
		}
		seen[name] = true
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s shipped in a release and is gone", name))
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != want {
			problems = append(problems, fmt.Sprintf("%s shipped in a release and changed (sha256 %s, released %s)", name, got, want))
		}
	}
	for i := 1; i <= floor; i++ {
		prefix := fmt.Sprintf("%03d_", i)
		listed := false
		for name := range seen {
			listed = listed || strings.HasPrefix(name, prefix)
		}
		if !listed {
			problems = append(problems, fmt.Sprintf("migration %s* shipped in a release and is not listed; the list only grows", prefix))
		}
	}
	return problems, len(seen), sc.Err()
}

// TestReleasedMigrationsNeverChange holds every migration a release
// shipped to its released bytes: a guard change is a new migration file.
func TestReleasedMigrationsNeverChange(t *testing.T) {
	problems, listed, err := releasedMigrationProblems("schema", releasedList, releasedFloor)
	if err != nil {
		t.Fatal(err)
	}
	if listed == 0 {
		t.Fatal("the released list names no migration: the rule checks nothing")
	}
	for _, p := range problems {
		t.Errorf("%s\n\ta released migration never changes; put the change in a new schema file", p)
	}
}

func TestReleasedMigrationsCatchAChange(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(body string) string {
		s := sha256.Sum256([]byte(body))
		return hex.EncodeToString(s[:])
	}
	write("001_a.sql", "CREATE TABLE a ();\n")
	write("002_b.sql", "CREATE TABLE b ();\n")
	list := filepath.Join(dir, "released.sha256")
	write("released.sha256", "# shipped\n"+
		sum("CREATE TABLE a ();\n")+"  001_a.sql\n"+
		sum("CREATE TABLE b ();\n")+"  002_b.sql\n"+
		sum("CREATE TABLE c ();\n")+"  003_c.sql\n")

	problems, listed, err := releasedMigrationProblems(dir, list, 3)
	if err != nil {
		t.Fatal(err)
	}
	if listed != 3 || len(problems) != 1 || !strings.Contains(problems[0], "003_c.sql shipped in a release and is gone") {
		t.Fatalf("a gone file: listed %d, problems %q", listed, problems)
	}

	write("003_c.sql", "CREATE TABLE c ();\n")
	if problems, _, _ := releasedMigrationProblems(dir, list, 3); len(problems) != 0 {
		t.Fatalf("unchanged files: %q", problems)
	}

	write("002_b.sql", "CREATE TABLE b (id int);\n")
	problems, _, _ = releasedMigrationProblems(dir, list, 3)
	if len(problems) != 1 || !strings.Contains(problems[0], "002_b.sql shipped in a release and changed") {
		t.Fatalf("a changed file: %q", problems)
	}

	write("002_b.sql", "CREATE TABLE b ();\n")
	write("released.sha256", sum("CREATE TABLE a ();\n")+"  001_a.sql\n"+sum("CREATE TABLE c ();\n")+"  003_c.sql\n")
	problems, _, _ = releasedMigrationProblems(dir, list, 3)
	if len(problems) != 1 || !strings.Contains(problems[0], "migration 002_* shipped in a release and is not listed") {
		t.Fatalf("a line dropped under the floor: %q", problems)
	}
}
