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
	// reinstall: an install below this version cannot be updated to it; it
	// is removed and set up again. The update floor (updatableFrom) is the
	// highest such version. It is not nonBreaking's opposite: nonBreaking
	// says whether an engine serves an agent on a guard without the
	// version, and an update to it keeps the data; reinstall says no update
	// reaches it from below at all.
	reinstall bool
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
	// versionSetupCodeLife shortens setup-code life to 10 minutes and
	// gives record_setup's EXPIRED a 30-minute grace: schema/017.
	versionSetupCodeLife
	// versionEngineAddressRemoved drops the engine address with the direct
	// transport: record_engine takes the key alone: schema/018.
	versionEngineAddressRemoved
	// versionRevertFilterName refuses a tables entry of a revert scope
	// descriptor that is not one schema.table name with its own detail,
	// NAME, naming the entry: schema/019.
	versionRevertFilterName
	// versionStoreNeutral writes every text a person signs, and the
	// ledger's fields, in the store-neutral form (CONTRACT.md, Stores),
	// and names agents agent:<name> from a record of their names. Clean
	// state: the chain does not verify rows written before it, so an
	// install from before reinstalls: schema/020 to 023.
	versionStoreNeutral
	// versionGuardTypedDetails gives apply_revert's REVERT_INVALID for a
	// revert already applied or signed, a revoked passkey and rows changed
	// since the preview, and NOTHING_TO_REVERT for a scope with no row to
	// restore, a code as their detail and the sentence as their hint, and
	// names the bad entry of a revert scope descriptor: schema/024.
	versionGuardTypedDetails
	// versionRefusalResources gives record_refusal the resources the
	// refused statement names, recorded on the change and in the ledger
	// row's detail: schema/025.
	versionRefusalResources
	// versionRefusalCut cuts a refusal's over-long intent, statement or
	// reason with a marker and replaces over-long params with one, instead
	// of raising, and gives REVERT_INVALID for a revert the role did not
	// prepare and APPROVAL_INVALID for an approval it does not hold the
	// codes NO_SUCH_REVERT and NO_SUCH_APPROVAL as their detail: schema/026.
	versionRefusalCut
	// versionRelease records, in schema_version, the BasaltDB release that
	// wrote each version (planRelease): schema/027.
	versionRelease
	// versionWithdraw lets the agent withdraw its own held write, revert or
	// plugin approval while it waits for the person, and refuses a
	// signature of a withdrawn one: schema/028. Breaking: the engine reads
	// the withdrawal from the agent views.
	versionWithdraw
)

// StoreNeutralVersion is the basalt_meta version that writes store-neutral
// texts and records agent names. Breaking: an engine needs it.
const StoreNeutralVersion = versionStoreNeutral

// EngineAddressRemovedVersion is the basalt_meta version whose
// record_engine takes the key alone.
const EngineAddressRemovedVersion = versionEngineAddressRemoved

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
var versionFiles = []int{versionGuard: guardFiles, versionInstallIDs: 1, versionPluginEvents: 1, versionPluginTrustRemoved: 1, versionPluginApprovals: 1, versionTrustPins: 1, versionSetupCodeLife: 1, versionEngineAddressRemoved: 1, versionRevertFilterName: 1, versionStoreNeutral: storeNeutralFiles, versionGuardTypedDetails: 1, versionRefusalResources: 1, versionRefusalCut: 1, versionRelease: 1, versionWithdraw: 1}

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
// versionSetupCodeLife: without it record_setup still uses the 24-hour
// bound and refuses EXPIRED with no grace; every tool is served as before.
// versionEngineAddressRemoved: the engine reads only an engine's key and
// revocation from agent_engines, which a guard without it has too; only
// basalt init records an engine, after the migrations.
// versionRevertFilterName: without it a badly formed name in a revert
// filter is refused as SHAPE with a hint that names no entry, which the
// engine answers as a refused scope (INVALID_ARGUMENT with that hint);
// every tool is served as before. versionRelease: only the setup reads
// the release column, to name the release of a guard too old to update;
// an engine never reads it.
var nonBreakingVersions = map[int]bool{
	versionPluginEvents: true, versionPluginTrustRemoved: true, versionPluginApprovals: true, versionTrustPins: true, versionSetupCodeLife: true,
	versionEngineAddressRemoved: true, versionRevertFilterName: true, versionRelease: true,
}

// reinstallVersions are the versions an older install is never updated to
// (migration.reinstall): it is removed and set up again. A guard change that
// cannot be applied over an older install sets its version here and nothing
// else, and CHANGELOG.md names it under "Breaking for alpha installs". The
// same release bumps config.BreakingEpoch: the setup page replaces such a
// guard only in an INSTALL, which only an engine with no config runs.
// versionInstallIDs: every 0.0.1 release shipped only version 1, and its
// SQL is different from today's version 1 (schema/001, 004, 005 and 006
// changed after it), so versions 2 and later were not written for it.
var reinstallVersions = map[int]bool{versionInstallIDs: true}

// guardFiles is how many schema files version 1 has: 001 to 011.
const guardFiles = 11

// storeNeutralFiles is how many schema files versionStoreNeutral has: 020
// (agent names and the ledger), 021 (approvals), 022 (reverts) and 023
// (plugin approvals).
const storeNeutralFiles = 4

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
		out = append(out, migration{version: v, sql: strings.Join(files[next:end], ""), nonBreaking: nonBreakingVersions[v], reinstall: reinstallVersions[v]})
		next = end
	}
	if next != len(files) {
		panic(fmt.Sprintf("schema: %d files belong to no version", len(files)-next))
	}
	return out
}

// updatableFrom is the update floor: the lowest installed version this
// build updates in place, the highest version marked reinstall (1 when
// none is). A guard below it is unusable (CheckUsable), and the engine
// tells the person to remove it and set up again instead of offering the
// update (guardmodel.Status.BelowFloor).
func updatableFrom() int { return floorOf(migrations) }

// floorOf is the update floor of ms: the highest version marked reinstall,
// else versionGuard.
func floorOf(ms []migration) int {
	floor := versionGuard
	for _, m := range ms {
		if m.reinstall {
			floor = max(floor, m.version)
		}
	}
	return floor
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
