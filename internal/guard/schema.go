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
	versionGuard               = iota + 1 // M1: guard, ledger, chain, retention
	versionChainFrom                      // M1 close-out: verify_chain_from, engine events
	versionReads                          // M1.5: recorded reads and STALE_READ
	versionApprovals                      // M2: passkeys, held writes and approvals
	versionRevertPlan                     // M3: the revert plan, read-only
	versionRevertTrial                    // M3: the trial run and prepared reverts
	versionRevertApply                    // M3: apply a signed revert
	versionRLS                            // M3 follow-up: the guard's row-level security policy
	versionRevertBatches                  // M3 follow-up: large reverts, signed once and applied in batches
	versionAgentsInherit                  // M4: agents are roles that inherit the agents group
	versionAgentPolicy                    // M4: ledger row for an agent RLS policy the person confirmed
	versionPasskeys                       // M4.1: passkey revocation and last use
	versionAgentVersion                   // M4 follow-up: agents read schema_version
	versionRunsAgent                      // M4.1: index for list_runs, the agent's own runs by id
	versionPII                            // M5.1: PII classification
	versionSetups                         // M4: setups recorded by basalt init --setup-code
	versionRevertSample                   // M3 follow-up: a large plan's sample shows both restored and skipped rows
	versionSetupRole                      // M4 follow-up: record_setup reads the clock and checks the agent role strictly
	versionPIIOids                        // M5.1 follow-up: pii_fingerprint names columns by oid and quotes names
	versionRevertScope                    // RS-1 to RS-4: a revert's scope descriptor, own work only for agents
	versionRevertWiden                    // RS-2, RS-5: the widen proof, rescope and reset, redaction after a widen
	versionRevertNonce                    // RS-2: the requesting role reads its revert's rescope nonce
	versionRevertReject                   // RS-2, Q8: the person rejects a pending revert
	versionSearchPath                     // the caller's temporary tables never shadow the catalog
	versionExpiryClock                    // approval and revert deadlines read the wall clock
	versionTriggerAlways                  // guard triggers fire under any session_replication_role
	versionPIIUsage                       // EV-14: a PII column needs USAGE on its schema
	versionOneClock                       // the person's acts recorded on the wall clock; search_path on every routine
	versionRevealRevert                   // HR-1: the person reveals a revert's redacted lines with a passkey proof
	versionRevealApproval                 // HR-1, HR-2: the person reveals a held approval's redacted lines through a re-run preview
	versionRevealNoLock                   // the approval reveal reads the approval row unlocked, so it never deadlocks with a signature
	versionCatalogChangeAgents            // Q-11: the proven revert scope catalog maps each change to its agent
	versionEngines                        // VC-21: engine keys, the pinned address and revocation
	versionPinnedTrigger                  // guard_row stores row images in fixed TimeZone, styles, float digits and lc_monetary
	versionPinnedReverts                  // bytea_output pinned too; the revert's row reads and restores pinned like guard_row
	versionReinstalls                     // reinstalls on the record: installs, record_pin_set_aside, pin_on_chain, agent_reinstalls
	versionHeldLines                      // a held write keeps preview lines over 64 KiB, up to 64 MiB in all
)

// migrations lists every version in order, each the schema files from
// first to last (their sequence numbers, inclusive).
var migrations = []migration{
	{version: versionGuard, sql: schemaFiles(1, 8)},
	{version: versionChainFrom, sql: schemaFiles(9, 10)},
	{version: versionReads, sql: schemaFiles(11, 12)},
	{version: versionApprovals, sql: schemaFiles(13, 18)},
	{version: versionRevertPlan, sql: schemaFiles(19, 20)},
	{version: versionRevertTrial, sql: schemaFiles(21, 22)},
	{version: versionRevertApply, sql: schemaFiles(23, 24)},
	{version: versionRLS, sql: schemaFiles(25, 25)},
	{version: versionRevertBatches, sql: schemaFiles(26, 31)},
	{version: versionAgentsInherit, sql: schemaFiles(32, 32)},
	{version: versionAgentPolicy, sql: schemaFiles(33, 33)},
	{version: versionPasskeys, sql: schemaFiles(34, 34)},
	{version: versionAgentVersion, sql: schemaFiles(35, 35)},
	{version: versionRunsAgent, sql: schemaFiles(36, 36)},
	{version: versionPII, sql: schemaFiles(37, 39)},
	{version: versionSetups, sql: schemaFiles(40, 42)},
	{version: versionRevertSample, sql: schemaFiles(43, 43)},
	{version: versionSetupRole, sql: schemaFiles(44, 44)},
	{version: versionPIIOids, sql: schemaFiles(45, 45)},
	{version: versionRevertScope, sql: schemaFiles(46, 50)},
	{version: versionRevertWiden, sql: schemaFiles(51, 53)},
	{version: versionRevertNonce, sql: schemaFiles(54, 54)},
	{version: versionRevertReject, sql: schemaFiles(55, 55)},
	{version: versionSearchPath, sql: schemaFiles(56, 57)},
	{version: versionExpiryClock, sql: schemaFiles(58, 59)},
	{version: versionTriggerAlways, sql: schemaFiles(60, 60)},
	{version: versionPIIUsage, sql: schemaFiles(61, 61)},
	{version: versionOneClock, sql: schemaFiles(62, 63)},
	{version: versionRevealRevert, sql: schemaFiles(64, 64)},
	{version: versionRevealApproval, sql: schemaFiles(65, 65)},
	{version: versionRevealNoLock, sql: schemaFiles(66, 66)},
	{version: versionCatalogChangeAgents, sql: schemaFiles(67, 67), nonBreaking: true},
	{version: versionEngines, sql: schemaFiles(68, 70), nonBreaking: true},
	{version: versionPinnedTrigger, sql: schemaFiles(71, 71), nonBreaking: true},
	{version: versionPinnedReverts, sql: schemaFiles(72, 72), nonBreaking: true},
	{version: versionReinstalls, sql: schemaFiles(73, 75), nonBreaking: true},
	{version: versionHeldLines, sql: schemaFiles(76, 76), nonBreaking: true},
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

// recordInstallRow writes the current install's row: on an upgrade to
// version 36 (the time of the upgrade), and on every install after it, when
// nothing changes for an install that has one (installed_at kept).
// basalt.vault_user is the Vault user the install ran for, set by the
// Vault's install path; null otherwise.
const recordInstallRow = `
INSERT INTO basalt_meta.installs (install, installed_at, installed_by, vault_user)
SELECT n.oid, pg_catalog.clock_timestamp(), session_user,
       NULLIF(pg_catalog.current_setting('basalt.vault_user', true), '')
  FROM pg_catalog.pg_namespace n
 WHERE n.nspname = 'basalt_meta'
ON CONFLICT (install) DO NOTHING;
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

// schemaFiles is the SQL of the schema files from sequence first to last,
// inclusive, concatenated in order.
func schemaFiles(first, last int) string {
	return strings.Join(schema[first-1:last], "")
}

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
