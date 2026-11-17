package guard

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// The SQL installed in the person's database, in basalt_meta, lives in the
// files of schema/, run in name order. Every migration runs as the guard
// role (owner of basalt_meta) with search_path = pg_catalog, pg_temp, so
// every object is schema-qualified.
//
// Role names reach this SQL only through Names.render, which replaces the
// {{guard}} and {{agents}} tokens with names that matched identPattern
// (lowercase, so the same token is valid as an identifier and inside a
// string literal). fmt.Sprintf is not used: the PL/pgSQL bodies are full of
// format('%s') calls.
//
// Forward-only: never edit an applied migration; add a new version.

// migration is one forward-only schema version.
type migration struct {
	version int
	sql     string
	// nonBreaking marks a version an engine serves an agent without
	// (CONTRACT.md, basalt_meta, AE-11): only GUARD_UPGRADE_AVAILABLE then.
	// Breaking is the default; setting it needs the engine test that serves
	// an agent on a guard without this version.
	nonBreaking bool
}

// basalt_meta versions, in order.
const (
	// versionGuard is the whole guard: every file of schema/.
	versionGuard = iota + 1
)

// migrations lists every version in order. A new version appends its own
// schema files after the last and its entry here; version 1 then stays the
// files it has now.
var migrations = []migration{
	{version: versionGuard, sql: strings.Join(schema, "")},
}

// LatestVersion is the basalt_meta version this build installs.
func LatestVersion() int { return migrations[len(migrations)-1].version }

// schemaVersionTable is created before any migration so the installer can
// read the installed version.
const schemaVersionTable = `
CREATE TABLE IF NOT EXISTS basalt_meta.schema_version (
    version    int         PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON basalt_meta.schema_version FROM PUBLIC;
`

// recordInstallRow writes the current install's row, on every install;
// nothing changes for an install that has one (installed_at kept).
// basalt.vault_user is the Vault user the install ran for, set by the
// Vault's install path; null otherwise.
const recordInstallRow = `
INSERT INTO basalt_meta.installs (id, install, installed_at, installed_by, vault_user)
VALUES (true, pg_catalog.gen_random_uuid(), pg_catalog.clock_timestamp(), session_user,
        NULLIF(pg_catalog.current_setting('basalt.vault_user', true), ''))
ON CONFLICT (id) DO NOTHING;
`

// recordInstall is recordInstallRow as its own init step, after the
// migrations: it runs as the owner, which alone may write installs.
const recordInstall = `
SET LOCAL ROLE {{guard}};
SET LOCAL search_path = pg_catalog, pg_temp;
` + recordInstallRow + `
RESET search_path;
RESET ROLE;`

// The schema files: schema/NNN_name.sql, NNN a zero-padded sequence, so
// the directory lists in the order the files run. Each file starts with a
// header, one or more lines starting with "--" and no blank line, then a
// blank line; the SQL that runs is the rest of the file from that blank
// line's newline on, so the header is documentation only and never runs.
//
// recordInstallLine is the one line the loader replaces: the file that
// creates basalt_meta.installs writes the current install's row with the
// same statement recordInstall runs, so that statement lives here once.
const recordInstallLine = "{{record_install_row}}\n"

//go:embed schema/*.sql
var schemaFS embed.FS

// schema is every schema file's SQL, in name order.
var schema = mustLoadSchema(schemaFS)

// mustLoadSchema reads the schema files. A malformed file is a broken
// build, so it panics (TestSchemaFiles covers the rules).
func mustLoadSchema(fsys fs.FS) []string {
	out, err := loadSchema(fsys)
	if err != nil {
		panic(err)
	}
	return out
}

// loadSchema returns the SQL of every .sql file under schema/ of fsys, in
// name order: each file numbered from 1 with no gap, its header dropped,
// recordInstallLine replaced. The line must appear exactly once in all.
func loadSchema(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, "schema")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	tokens := 0
	for i, e := range entries {
		name := e.Name()
		if want := fmt.Sprintf("%03d_", i+1); !strings.HasPrefix(name, want) || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("schema/%s: want a name starting %s and ending .sql", name, want)
		}
		b, err := fs.ReadFile(fsys, "schema/"+name)
		if err != nil {
			return nil, err
		}
		sql, err := schemaSQL(string(b))
		if err != nil {
			return nil, fmt.Errorf("schema/%s: %w", name, err)
		}
		tokens += strings.Count(sql, recordInstallLine)
		out = append(out, strings.ReplaceAll(sql, recordInstallLine, recordInstallRow))
	}
	if tokens != 1 {
		return nil, fmt.Errorf("schema: %q appears %d times, want once", strings.TrimSpace(recordInstallLine), tokens)
	}
	return out, nil
}

// schemaSQL is the SQL of one schema file: the file without its header.
func schemaSQL(file string) (string, error) {
	header, rest, ok := strings.Cut(file, "\n\n")
	if !ok || header == "" {
		return "", fmt.Errorf("no header: want -- lines, then a blank line")
	}
	for line := range strings.SplitSeq(header, "\n") {
		if !strings.HasPrefix(line, "--") {
			return "", fmt.Errorf("header line %q does not start with --", line)
		}
	}
	return "\n" + rest, nil
}
