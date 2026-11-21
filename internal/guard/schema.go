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
	// versionGuard is the whole guard as first released: schema/001 to 011.
	versionGuard = iota + 1
	// versionInstallIDs identifies an install by a random id instead of
	// the basalt_meta schema oid: schema/012.
	versionInstallIDs
	// versionPluginEvents adds record_plugin_event: schema/013.
	versionPluginEvents
	// versionPluginTrustRemoved lets record_plugin_event record
	// PLUGIN_TRUST_REMOVED: schema/014.
	versionPluginTrustRemoved
	// versionPluginApprovals adds plugin approvals verified by passkey and
	// the signer of a plugin event: schema/015.
	versionPluginApprovals
	// versionTrustPins adds record_trust_pin and agent_trust_pins: schema/016.
	versionTrustPins
)

// TrustPinsVersion is the basalt_meta version that records trust pins. A
// guard below it has no record to compare a pin with.
const TrustPinsVersion = versionTrustPins

// PluginApprovalsVersion is the basalt_meta version that holds plugin
// approvals (open_plugin_approval, submit_plugin_approval,
// agent_plugin_approvals). A guard below it cannot open one.
const PluginApprovalsVersion = versionPluginApprovals

// versionFiles is how many schema files each version runs, in version
// order: a new version appends its own schema files after the last and its
// count here, and every earlier version keeps the files it has.
var versionFiles = []int{versionGuard: guardFiles, versionInstallIDs: 1, versionPluginEvents: 1, versionPluginTrustRemoved: 1, versionPluginApprovals: 1, versionTrustPins: 1}

// nonBreakingVersions are the versions an engine serves an agent without
// (migration.nonBreaking). versionPluginEvents: without it the engine
// cannot record a plugin event, so it serves no plugin to that agent and
// everything else as before. versionPluginTrustRemoved: without it the
// engine cannot correct a PLUGIN_TRUST_ADDED for a key it does not trust,
// and logs that; everything is served as before. versionPluginApprovals:
// without it an entry that requires approval is withheld from that agent
// and no approval can be opened there; everything else is served as before.
// versionTrustPins: without it basalt init records no pin and status has
// nothing to compare a pin with; everything is served as before.
var nonBreakingVersions = map[int]bool{versionPluginEvents: true, versionPluginTrustRemoved: true, versionPluginApprovals: true, versionTrustPins: true}

// guardFiles is how many schema files version 1 has: 001 to 011.
const guardFiles = 11

// migrations lists every version in order.
var migrations = mustSplitMigrations(schema, versionFiles)

// mustSplitMigrations groups the schema files into versions by count. A
// count that does not match the files is a broken build, so it panics
// (TestSchemaFiles covers it).
func mustSplitMigrations(files []string, counts []int) []migration {
	out := make([]migration, 0, len(counts))
	next := 0
	for v := versionGuard; v < len(counts); v++ {
		end := next + counts[v]
		if end > len(files) {
			panic(fmt.Sprintf("schema: version %d needs %d files, %d left", v, counts[v], len(files)-next))
		}
		out = append(out, migration{version: v, sql: strings.Join(files[next:end], ""), nonBreaking: nonBreakingVersions[v]})
		next = end
	}
	if next != len(files) {
		panic(fmt.Sprintf("schema: %d files belong to no version", len(files)-next))
	}
	return out
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

// recordInstallRowV1 is version 1's statement (schema/001, where it is
// written out as it shipped): installs keyed by the basalt_meta schema oid.
const recordInstallRowV1 = `
INSERT INTO basalt_meta.installs (install, installed_at, installed_by, vault_user)
SELECT n.oid, pg_catalog.clock_timestamp(), session_user,
       NULLIF(pg_catalog.current_setting('basalt.vault_user', true), '')
  FROM pg_catalog.pg_namespace n
 WHERE n.nspname = 'basalt_meta'
ON CONFLICT (install) DO NOTHING;
`

// recordInstall is the install row statement of version v, the version the
// guard is at after the migrations, as its own init step: it runs as the
// owner, which alone may write installs. An install that stops at version
// 1 (Options.UpTo) still has version 1's installs table.
func recordInstall(v int) string {
	row := recordInstallRow
	if v < versionInstallIDs {
		row = recordInstallRowV1
	}
	return `
SET LOCAL ROLE {{guard}};
SET LOCAL search_path = pg_catalog, pg_temp;
` + row + `
RESET search_path;
RESET ROLE;`
}

// The schema files: schema/NNN_name.sql, NNN a zero-padded sequence, so
// the directory lists in the order the files run. Each file starts with a
// header, one or more lines starting with "--" and no blank line, then a
// blank line; the SQL that runs is the rest of the file from that blank
// line's newline on, so the header is documentation only and never runs.
//
// recordInstallLine is the one line the loader replaces: the file that
// gives basalt_meta.installs its current shape (schema/012) writes the
// current install's row with the same statement recordInstall runs, so
// that statement lives here once.
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
