package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/supabase"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Querier is the part of a pgx connection, pool or transaction this
// package needs. It is an alias of the interface itself, so the setup
// service's port, which cannot import this package, names the same type.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const (
	// passwordBytes of randomness in a generated agent password (hex encoded).
	passwordBytes = 32
	redacted      = "********"
)

// ErrSetupCollided is a setup step Postgres stopped to break a deadlock
// with another session, most often autovacuum's ANALYZE on a table the
// setup attaches a trigger to. The transaction rolled back, so running the
// setup again is safe.
var ErrSetupCollided = errors.New("a database maintenance task (such as autovacuum) locked a table while the setup changed it, " +
	"and Postgres stopped the setup to break the deadlock; run the setup again")

// sqlstateDeadlock is Postgres's deadlock_detected.
const sqlstateDeadlock = "40P01"

// ApplyScript runs the script on tx. The caller commits. A step stopped by
// a deadlock says so in plain words (ErrSetupCollided).
func ApplyScript(ctx context.Context, tx pgx.Tx, s guardmodel.Script) error {
	for i, st := range s.Statements {
		_, err := tx.Exec(ctx, st.SQL)
		if err == nil {
			continue
		}
		if isDeadlock(err) {
			return fmt.Errorf("init step %d: %w: %w", i+1, ErrSetupCollided, err)
		}
		return fmt.Errorf("init step %d: %w", i+1, err)
	}
	return nil
}

func isDeadlock(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == sqlstateDeadlock
}

// NewPassword returns a random password for an agent role. Hex only, so
// it is safe inside a SQL literal.
func NewPassword() string {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// InstalledVersion returns the installed basalt_meta version, 0 when none.
func InstalledVersion(ctx context.Context, q Querier) (int, error) {
	var exists bool
	// Plain SQL: catalog lookup.
	if err := q.QueryRow(ctx, `SELECT to_regclass('basalt_meta.schema_version') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var v int
	// Plain SQL: an aggregate over the version table.
	err := q.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM basalt_meta.schema_version`).Scan(&v)
	return v, err
}

// PlanInit builds the script that installs or upgrades basalt_meta,
// creates or rotates the agent role, grants its tables and attaches the
// guard. It reads the database (installed version, table sequences) but
// changes nothing.
func PlanInit(ctx context.Context, q Querier, opts guardmodel.InitOptions) (guardmodel.Script, error) {
	n := opts.Names
	if err := n.Validate(); err != nil {
		return guardmodel.Script{}, err
	}
	// An install over a basalt_meta this build cannot use would fail midway
	// (for one from before the versions started again, on 42P01 relation
	// "basalt_meta.installs" does not exist): refuse it before any SQL.
	if err := CheckUsable(ctx, q); err != nil {
		return guardmodel.Script{}, err
	}
	// Before anything else, so a missing table fails init with one message.
	if err := checkTablesExist(ctx, q, opts.Agent); err != nil {
		return guardmodel.Script{}, err
	}
	version, err := InstalledVersion(ctx, q)
	if err != nil {
		return guardmodel.Script{}, err
	}
	var s guardmodel.Script
	warning, err := replicationRoleWarning(ctx, q)
	if err != nil {
		return guardmodel.Script{}, err
	}
	if warning != "" {
		s.Warnings = append(s.Warnings, warning)
	}
	add := func(sql string) { s.Statements = append(s.Statements, guardmodel.Statement{SQL: renderSQL(n, sql)}) }
	add(installRoles)
	add(installSchema)
	for _, m := range migrations {
		if m.version <= version || (opts.UpTo > 0 && m.version > opts.UpTo) {
			continue
		}
		add(migrationBegin + m.sql + fmt.Sprintf(migrationEnd, m.version))
	}
	add(recordInstall(versionAfter(version, opts.UpTo)))
	if opts.Agent.Name != "" {
		agent, err := planAgent(ctx, q, n, opts.Agent, versionAfter(version, opts.UpTo))
		if err != nil {
			return guardmodel.Script{}, err
		}
		s.Statements = append(s.Statements, agent...)
		role, err := n.Agent(opts.Agent.Name)
		if err != nil {
			return guardmodel.Script{}, err
		}
		for _, b := range opts.AgentPolicies {
			s.Statements = append(s.Statements, agentPolicy(role, b))
		}
	}
	add(attachAll)
	return s, nil
}

// installRoles creates the owner and group roles once, and lets the admin
// act as the owner (needed to create objects owned by it).
const installRoles = `
SELECT pg_advisory_xact_lock(hashtext('basalt_meta install'));
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{{guard}}') THEN
        CREATE ROLE {{guard}} NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{{agents}}') THEN
        CREATE ROLE {{agents}} NOLOGIN;
    END IF;
END $$;
GRANT {{guard}} TO CURRENT_USER;`

const installSchema = `
CREATE SCHEMA IF NOT EXISTS basalt_meta AUTHORIZATION {{guard}};`

// migrationBegin and migrationEnd wrap one migration: it runs as the owner
// with a safe search_path and records its version (%d in migrationEnd).
const migrationBegin = `
SET LOCAL ROLE {{guard}};
SET LOCAL search_path = pg_catalog, pg_temp;
` + schemaVersionTable

const migrationEnd = `
INSERT INTO basalt_meta.schema_version (version) VALUES (%d);
RESET search_path;
RESET ROLE;`

const attachAll = `
SELECT count(1) FROM basalt_meta.attach_all();`

// planAgent creates or rotates the agent role, grants its tables and, on a
// guard at version (after the migrations) that keeps agent names, records
// the agent's name with its role.
func planAgent(ctx context.Context, q Querier, n guardmodel.Names, spec guardmodel.AgentSpec, version int) ([]guardmodel.Statement, error) {
	role, err := n.Agent(spec.Name)
	if err != nil {
		return nil, err
	}
	if err := checkAgentPassword(spec); err != nil {
		return nil, err
	}
	timeout := spec.StatementTimeout
	if timeout <= 0 {
		timeout = guardmodel.DefaultRoleStatementTimeout
	}
	grants, err := planGrants(ctx, q, role, spec)
	if err != nil {
		return nil, err
	}
	adopt, err := agentAdoptStatement(n, role, spec)
	if err != nil {
		return nil, err
	}
	st, err := agentRoleStatement(n, role, spec, timeout.Milliseconds())
	if err != nil {
		return nil, err
	}
	out := []guardmodel.Statement{adopt}
	switch {
	case spec.Change && spec.KeepGrants:
		out = append(out, guardmodel.Statement{SQL: renderSQL(n, fmt.Sprintf(agentMemberSQL, role))})
	case spec.Change:
		out = append(out, guardmodel.Statement{SQL: renderSQL(n, fmt.Sprintf(agentChangeSQL, role))})
	}
	out = append(out, st)
	if version >= versionStoreNeutral {
		out = append(out, agentNameStatement(n, role, spec.Name))
	}
	if spec.Exact {
		exact, err := agentExactStatement(role, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, exact)
	}
	return append(out, grants...), nil
}

// agentNameSQL records an agent's name with its role (%[1]s, %[2]s: quoted
// literals), as the owner, so the guard writes agent:<name> in texts from
// it (CONTRACT.md, Stores, Agent names). A role keeps the name it has.
const agentNameSQL = `
SET LOCAL ROLE {{guard}};
INSERT INTO basalt_meta.agent_names (role, name) VALUES (%[1]s, %[2]s) ON CONFLICT (role) DO NOTHING;
RESET ROLE;`

// agentNameStatement is agentNameSQL for role and the agent's name.
func agentNameStatement(n guardmodel.Names, role, name string) guardmodel.Statement {
	return guardmodel.Statement{SQL: renderSQL(n, fmt.Sprintf(agentNameSQL, quoteLiteral(role), quoteLiteral(name)))}
}

// agentExactStatement is agentExactSQL for role and spec's tables.
func agentExactStatement(role string, spec guardmodel.AgentSpec) (guardmodel.Statement, error) {
	literals := func(names []string) (string, error) {
		out := make([]string, 0, len(names))
		for _, name := range names {
			t, err := parseTable(name)
			if err != nil {
				return "", err
			}
			out = append(out, quoteLiteral(t.ident()))
		}
		return strings.Join(out, ", "), nil
	}
	write, err := literals(spec.Write)
	if err != nil {
		return guardmodel.Statement{}, err
	}
	read, err := literals(spec.Read)
	if err != nil {
		return guardmodel.Statement{}, err
	}
	return guardmodel.Statement{SQL: fmt.Sprintf(agentExactSQL, role, write, read)}, nil
}

// agentExactFrom, agentExactOwned and agentExactKinds make the query of
// agentExactSQL: each privilege the setup grants (planGrants) that the role
// holds beyond its picked tables. That is SELECT, INSERT, UPDATE or DELETE
// on a table that is not picked, INSERT, UPDATE or DELETE on a table picked
// to read, and USAGE or SELECT on a serial sequence of a table not picked
// to write. Only where the setup grants: ordinary and partitioned tables
// with plain lowercase names outside the system schemas and basalt_meta,
// and their serial sequences. Schema USAGE is left: it reaches no row by
// itself. agentExactOwned narrows it to relations whose owner this admin
// acts for (it is the owner, a member of it that inherits, or a
// superuser): Postgres records its REVOKE as the owner's, so it removes
// the owner's grants.
const agentExactFrom = `
SELECT c.oid AS rel, c.relkind = 'S' AS seq, a.privilege_type AS priv
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
 WHERE a.grantee = v_role`

const agentExactOwned = `
   AND pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE')`

const agentExactKinds = `
   AND n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND n.nspname <> 'basalt_meta'
   AND n.nspname ~ '^[a-z_][a-z0-9_]{0,62}$'
   AND ((c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relname ~ '^[a-z_][a-z0-9_]{0,62}$'
         AND a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
         AND NOT (c.oid = ANY (v_write) OR (c.oid = ANY (v_read) AND a.privilege_type = 'SELECT')))
     OR (c.relkind = 'S' AND a.privilege_type IN ('USAGE', 'SELECT')
         AND EXISTS (SELECT 1 FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class o ON o.oid = d.refobjid
              WHERE d.objid = c.oid AND d.deptype = 'a' AND o.relkind IN ('r', 'p') AND NOT o.relispartition
                AND o.relname ~ '^[a-z_][a-z0-9_]{0,62}$')
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.objid = c.oid AND d.deptype = 'a' AND d.refobjid = ANY (v_write))))`

// agentExactSQL runs before the grants of a local install that finishes
// with a role that already exists (AgentSpec.Exact). It revokes what the
// query selects on relations whose owner this admin acts for, so after the
// grants that follow, in the same transaction, the role holds the setup's
// privileges on exactly the picked tables. It then reads the query again
// on every owner's relations: a privilege still left (on a relation whose
// owner this admin cannot act for, or granted by another role with a
// grant option) is refused (BS008, its detail
// guardmodel.UnpickedGrantsDetail and the relations), so the transaction
// rolls back rather than leave it in place. %[1]s is the validated role,
// %[2]s and %[3]s the write and read tables as SQL literals of validated
// identifiers.
const agentExactSQL = `
DO $$
DECLARE
    v_role  oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = '%[1]s');
    v_write oid[] := ARRAY[%[2]s]::text[]::pg_catalog.regclass[]::oid[];
    v_read  oid[] := ARRAY[%[3]s]::text[]::pg_catalog.regclass[]::oid[];
    v_rec   record;
    v_left  text;
BEGIN
    IF v_role IS NULL THEN
        RETURN; -- a new role holds nothing
    END IF;
    FOR v_rec IN SELECT u.rel::pg_catalog.regclass AS rel, u.seq,
            pg_catalog.string_agg(DISTINCT u.priv, ', ') AS privs
        FROM (` + agentExactFrom + agentExactOwned + agentExactKinds + `) u GROUP BY u.rel, u.seq LOOP
        EXECUTE pg_catalog.format('REVOKE %%s ON %%s %%s FROM %%I', v_rec.privs,
            CASE WHEN v_rec.seq THEN 'SEQUENCE' ELSE 'TABLE' END, v_rec.rel, '%[1]s');
    END LOOP;
    SELECT pg_catalog.string_agg(DISTINCT pg_catalog.format('%%I.%%I', ns.nspname, cl.relname), ', ') INTO v_left
        FROM (` + agentExactFrom + agentExactKinds + `) u
        JOIN pg_catalog.pg_class cl ON cl.oid = u.rel
        JOIN pg_catalog.pg_namespace ns ON ns.oid = cl.relnamespace;
    IF v_left IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s ` + guardmodel.UnpickedGrantsDetail + `' || v_left,
            HINT = 'Another role made those grants: that role, or the owner of the table or sequence, must revoke them (REVOKE ALL ON <table or sequence> FROM %[1]s); then finish the setup again.';
    END IF;
END $$;`

// agentMemberSQL runs after agentAdoptSQL for an AGENT setup code that
// keeps the role's grants: the role must be an agent of this install, and
// keeps every privilege it holds.
const agentMemberSQL = `
DO $$
DECLARE
    v_role oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = '%[1]s');
BEGIN
    IF v_role IS NULL OR NOT pg_catalog.pg_has_role(v_role, '{{agents}}', 'USAGE') THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not an agent role of {{agents}}: an AGENT setup code changes only an existing agent';
    END IF;
END $$;`

// agentChangeSQL runs after agentAdoptSQL for an AGENT setup code: the role
// must be an agent of this install, and loses every privilege it holds on
// a table, view or sequence, so the grants that follow are exactly the
// code's tables. A privilege this admin cannot revoke (granted by someone
// else) is refused rather than left in place.
const agentChangeSQL = `
DO $$
DECLARE
    v_role oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = '%[1]s');
    v_rel  pg_catalog.regclass;
BEGIN
    IF v_role IS NULL OR NOT pg_catalog.pg_has_role(v_role, '{{agents}}', 'USAGE') THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not an agent role of {{agents}}: an AGENT setup code changes only an existing agent';
    END IF;
    FOR v_rel IN SELECT DISTINCT c.oid::pg_catalog.regclass FROM pg_catalog.pg_class c
        WHERE EXISTS (SELECT 1 FROM pg_catalog.aclexplode(c.relacl) a WHERE a.grantee = v_role)
           OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute t, LATERAL pg_catalog.aclexplode(t.attacl) a
                WHERE t.attrelid = c.oid AND a.grantee = v_role) LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON %%s FROM %%I', v_rel, '%[1]s');
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a WHERE a.grantee = v_role)
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute t, LATERAL pg_catalog.aclexplode(t.attacl) a WHERE a.grantee = v_role) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s holds table privileges this admin cannot revoke',
            HINT = 'Have the role that granted them revoke them, or ask for a code for another agent name.';
    END IF;
END $$;`

// checkAgentPassword accepts at most one of a generated password and a
// verifier, and CreateOnly only with one of them.
func checkAgentPassword(spec guardmodel.AgentSpec) error {
	switch {
	case spec.Password != "" && spec.Verifier != "":
		return fmt.Errorf("%w: give a password or a verifier, not both", guardmodel.ErrInvalidAgent)
	case spec.Password != "" && !isHex(spec.Password):
		return fmt.Errorf("%w: password must be generated by NewPassword", guardmodel.ErrInvalidAgent)
	case spec.Verifier != "":
		return CheckVerifier(spec.Verifier)
	case spec.CreateOnly && spec.Password == "":
		return fmt.Errorf("%w: a new role needs a password or a verifier", guardmodel.ErrInvalidAgent)
	}
	return nil
}

// agentRoleStatement creates, rotates or keeps the agent role's password.
// The SQL never holds a plaintext password: a generated one is sent as its
// SCRAM-SHA-256 verifier, computed here, so a server log of the statement
// (log_statement, log_min_error_statement) cannot reveal it. What the person
// sees shows a generated password's verifier redacted, and a setup code's
// verifier as is.
func agentRoleStatement(n guardmodel.Names, role string, spec guardmodel.AgentSpec, timeoutMs int64) (guardmodel.Statement, error) {
	if spec.Password == "" && spec.Verifier == "" {
		return guardmodel.Statement{SQL: renderSQL(n, fmt.Sprintf(agentKeepRoleSQL, role, timeoutMs, setupcode.AgentConnectionLimit))}, nil
	}
	tmpl := agentRoleSQL
	switch {
	case spec.CreateOnly:
		tmpl = agentCreateRoleSQL
	case spec.Verifier != "":
		tmpl = agentAlterRoleSQL
	}
	render := func(verifier string) string {
		return renderSQL(n, fmt.Sprintf(tmpl, role, quoteLiteral(verifier), timeoutMs, setupcode.AgentConnectionLimit))
	}
	if spec.Verifier != "" {
		return guardmodel.Statement{SQL: render(spec.Verifier)}, nil
	}
	verifier, err := setupcode.NewVerifier(spec.Password)
	if err != nil {
		return guardmodel.Statement{}, fmt.Errorf("%w: %w", guardmodel.ErrInvalidAgent, err)
	}
	return guardmodel.Statement{SQL: render(verifier), Shown: render(redacted)}, nil
}

// quoteLiteral renders s as a SQL string literal (standard_conforming_strings).
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// AgentRoleExists reports whether the agent's role exists, so init can keep
// its password.
func AgentRoleExists(ctx context.Context, q Querier, n guardmodel.Names, agent string) (bool, error) {
	role, err := n.Agent(agent)
	if err != nil {
		return false, err
	}
	query, args, err := sq.Select("1").Prefix("SELECT EXISTS (").From("pg_catalog.pg_roles").
		Where(sq.Eq{"rolname": role}).Suffix(")").PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return false, err
	}
	var exists bool
	err = q.QueryRow(ctx, query, args...).Scan(&exists)
	return exists, err
}

// agentAdoptSQL runs before every agent role statement. When a role named
// %[1]s already exists, init is about to give it LOGIN, a password or the
// agents group, so it must be a plain agent; otherwise this refuses (BS008)
// and nothing changes. %[2]s is the agent's tables, as SQL literals of
// validated identifiers. The role is refused when:
//   - it, or a role it is a member of, has an elevated attribute;
//   - it is a member (directly or not, inheriting or not, so it could SET
//     ROLE) of any role but the agents group: an allow-list, so a new
//     predefined role is refused too (pg_has_role is true for the role
//     itself, and for every role when it is a superuser);
//   - it is a member of the owner of the database or of any object in it
//     (pg_shdepend): an owner can replace a function, view or default that
//     a guarded write runs, and so run code as the next writer;
//   - it holds a direct privilege on anything in basalt_meta, or TRUNCATE,
//     TRIGGER, REFERENCES or MAINTAIN on an agent or guarded table.
//
// Then it resets the role's own settings (ALTER ROLE ... SET), everywhere
// and in this database: a setting such as session_replication_role =
// replica would skip the guard's triggers. A setting the admin may not
// reset (one only a superuser may set, when the admin is not one) is
// refused.
const agentAdoptSQL = `
DO $$
DECLARE
    v_role   oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = '%[1]s');
    v_tables oid[] := ARRAY[%[2]s]::text[]::pg_catalog.regclass[]::oid[];
    v_db     pg_catalog.pg_database%%ROWTYPE;
BEGIN
    IF v_role IS NULL THEN
        RETURN; -- a new role: nothing to take over
    END IF;
    SELECT * INTO v_db FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database();
    v_tables := v_tables || ARRAY(SELECT t.tgrelid FROM pg_catalog.pg_trigger t WHERE t.tgname = 'basalt_guard');
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles g
        WHERE pg_catalog.pg_has_role(v_role, g.oid, 'MEMBER')
          AND (g.rolsuper OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolbypassrls
               OR (g.oid <> v_role AND g.rolname <> '{{agents}}'))) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not a plain agent role: it has elevated attributes, or is a member of a role other than {{agents}}',
            HINT = 'Remove those attributes and memberships from the role, or use another agent name.';
    END IF;
    IF pg_catalog.pg_has_role(v_role, v_db.datdba, 'MEMBER') OR EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend s
        WHERE s.dbid = v_db.oid AND s.deptype = 'o' AND s.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass
          AND pg_catalog.pg_has_role(v_role, s.refobjid, 'MEMBER')) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not a plain agent role: it owns, or is a member of the owner of, this database or an object in it',
            HINT = 'Reassign what it owns (REASSIGN OWNED BY %[1]s TO ...), or use another agent name.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c, LATERAL pg_catalog.aclexplode(c.relacl) a
        WHERE a.grantee = v_role
          AND (c.relnamespace = 'basalt_meta'::pg_catalog.regnamespace
               OR (c.oid = ANY (v_tables) AND a.privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES', 'MAINTAIN'))))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p, LATERAL pg_catalog.aclexplode(p.proacl) a
        WHERE p.pronamespace = 'basalt_meta'::pg_catalog.regnamespace AND a.grantee = v_role)
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, LATERAL pg_catalog.aclexplode(n.nspacl) a
        WHERE n.nspname = 'basalt_meta' AND a.grantee = v_role) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not a plain agent role: it holds privileges on basalt_meta, or TRUNCATE, TRIGGER, REFERENCES or MAINTAIN on an agent or guarded table',
            HINT = 'Revoke those privileges from the role, or use another agent name.';
    END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %%I RESET ALL', '%[1]s');
    EXECUTE pg_catalog.format('ALTER ROLE %%I IN DATABASE %%I RESET ALL', '%[1]s', v_db.datname);
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
        WHERE s.setrole = v_role AND s.setdatabase IN (0, v_db.oid)) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s has role settings this admin cannot reset',
            HINT = 'Have a superuser run ALTER ROLE %[1]s RESET ALL (and IN DATABASE), or use another agent name.';
    END IF;
END $$;`

// agentAdoptStatement is agentAdoptSQL for role and spec's tables.
func agentAdoptStatement(n guardmodel.Names, role string, spec guardmodel.AgentSpec) (guardmodel.Statement, error) {
	names := append(append([]string{}, spec.Write...), spec.Read...)
	tables := make([]string, 0, len(names))
	for _, name := range names {
		t, err := parseTable(name)
		if err != nil {
			return guardmodel.Statement{}, err
		}
		tables = append(tables, quoteLiteral(t.ident()))
	}
	return guardmodel.Statement{SQL: renderSQL(n, fmt.Sprintf(agentAdoptSQL, role, strings.Join(tables, ", ")))}, nil
}

// agentKeepRoleSQL updates an agent role that exists without touching its
// password. %[1]s is the validated role, %[2]d the statement timeout in ms,
// %[3]d the connection limit (AgentConnectionLimit).
const agentKeepRoleSQL = `
ALTER ROLE %[1]s LOGIN;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[2]d;
ALTER ROLE %[1]s CONNECTION LIMIT %[3]d;`

// agentRoleSQL creates or rotates one agent role. %[1]s is the validated
// role, %[2]s the SCRAM-SHA-256 verifier as a SQL literal, %[3]d the
// statement timeout in ms, %[4]d the connection limit
// (AgentConnectionLimit).
const agentRoleSQL = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '%[1]s') THEN
        CREATE ROLE %[1]s LOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %[2]s;
    ELSE
        ALTER ROLE %[1]s LOGIN PASSWORD %[2]s;
    END IF;
END $$;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;
ALTER ROLE %[1]s CONNECTION LIMIT %[4]d;`

// agentCreateRoleSQL creates a new agent role with a plain CREATE ROLE, so
// a role that exists is refused (an INSTALL setup code never takes over a
// role). %[1]s is the validated role, %[2]s the verifier as a SQL literal,
// %[3]d the statement timeout in ms, %[4]d the connection limit.
const agentCreateRoleSQL = `
CREATE ROLE %[1]s LOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %[2]s;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;
ALTER ROLE %[1]s CONNECTION LIMIT %[4]d;`

// agentAlterRoleSQL sets the password of an agent role that exists; a
// role that does not exist is refused. Arguments as agentCreateRoleSQL.
// The password comes from whoever made the setup code, so this must never
// reach a role that is not a plain agent: besides agentAdoptSQL it refuses
// (BS008) a role outside the agents group, and record_setup, run in the
// same transaction, checks the role again.
const agentAlterRoleSQL = `
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.rolname = '%[1]s' AND NOT pg_catalog.pg_has_role(r.oid, '{{agents}}', 'USAGE')) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not an agent role: a setup code cannot set its password';
    END IF;
END $$;
ALTER ROLE %[1]s LOGIN PASSWORD %[2]s;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;
ALTER ROLE %[1]s CONNECTION LIMIT %[4]d;`

// tableRef is a parsed "schema.table".
type tableRef struct{ schema, table string }

func (t tableRef) ident() string { return pgx.Identifier{t.schema, t.table}.Sanitize() }

func parseTable(s string) (tableRef, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	switch {
	case len(parts) == 1 && parts[0] != "":
		return tableRef{"public", parts[0]}, nil
	case len(parts) == 2 && parts[0] != "" && parts[1] != "":
		return tableRef{parts[0], parts[1]}, nil
	default:
		return tableRef{}, fmt.Errorf("%w: table %q must be schema.table", guardmodel.ErrInvalidAgent, s)
	}
}

// MissingTablesError lists the agent's --write and --read tables that do
// not exist, all of them, so init fails once with the whole list.
type MissingTablesError struct {
	// Tables are schema.table as given (public. added when unqualified).
	Tables []string
}

func (e *MissingTablesError) Error() string {
	return "tables not found: " + strings.Join(e.Tables, ", ")
}

// checkTablesExist returns a MissingTablesError naming every table of spec
// that does not exist. It only reads the catalog.
func checkTablesExist(ctx context.Context, q Querier, spec guardmodel.AgentSpec) error {
	var missing []string
	for _, name := range append(append([]string{}, spec.Write...), spec.Read...) {
		t, err := parseTable(name)
		if err != nil {
			return err
		}
		var exists bool
		// Plain SQL: catalog lookup of a quoted name.
		if err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, t.ident()).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			missing = append(missing, t.schema+"."+t.table)
		}
	}
	if len(missing) > 0 {
		return &MissingTablesError{Tables: missing}
	}
	return nil
}

func planGrants(ctx context.Context, q Querier, role string, spec guardmodel.AgentSpec) ([]guardmodel.Statement, error) {
	ident := pgx.Identifier{role}.Sanitize()
	var out []guardmodel.Statement
	grant := func(privs string, tables []string) error {
		for _, name := range tables {
			t, err := parseTable(name)
			if err != nil {
				return err
			}
			seqs, err := ownedSequences(ctx, q, t)
			if err != nil {
				return err
			}
			sql := fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s;\nGRANT %s ON %s TO %s;",
				pgx.Identifier{t.schema}.Sanitize(), ident, privs, t.ident(), ident)
			if privs != "SELECT" && len(seqs) > 0 {
				sql += fmt.Sprintf("\nGRANT USAGE, SELECT ON SEQUENCE %s TO %s;", strings.Join(seqs, ", "), ident)
			}
			out = append(out, guardmodel.Statement{SQL: sql})
		}
		return nil
	}
	if err := grant("SELECT", spec.Read); err != nil {
		return nil, err
	}
	if err := grant("SELECT, INSERT, UPDATE, DELETE", spec.Write); err != nil {
		return nil, err
	}
	return out, nil
}

// ownedSequences lists the serial sequences of a table (quoted). It also
// fails early when the table does not exist.
func ownedSequences(ctx context.Context, q Querier, t tableRef) ([]string, error) {
	// Plain SQL: pg_depend catalog join.
	rows, err := q.Query(ctx, `SELECT d.objid::regclass::text
		FROM pg_catalog.pg_depend d
		JOIN pg_catalog.pg_class s ON s.oid = d.objid AND s.relkind = 'S'
		WHERE d.refobjid = $1::regclass AND d.deptype = 'a'
		ORDER BY 1`, t.ident())
	if err != nil {
		return nil, fmt.Errorf("table %s: %w", t.ident(), err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// PlanUninstall is the SQL Uninstall runs, read from the catalog and
// changing nothing: the DROP POLICY of each policy named after an agent
// role or the guard role, the DROP SCHEMA of basalt_meta, and for each of
// those roles, the group and the owner that exists, its DROP OWNED and
// DROP ROLE. It always drops basalt_meta (IF EXISTS), so a plan on a
// database without Basalt still ends with that statement.
func PlanUninstall(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	agents, err := AgentRoles(ctx, q, n)
	if err != nil {
		return nil, err
	}
	var drops []string
	for _, role := range append(slices.Clone(agents), n.Guard()) {
		policies, err := namedPolicyDrops(ctx, q, role)
		if err != nil {
			return nil, err
		}
		drops = append(drops, policies...)
	}
	// Plain SQL: DDL.
	drops = append(drops, `DROP SCHEMA IF EXISTS basalt_meta CASCADE`)
	for _, role := range append(agents, n.Agents(), n.Guard()) {
		sql, err := roleDrop(ctx, q, role)
		if err != nil {
			return nil, err
		}
		if sql != "" {
			drops = append(drops, sql)
		}
	}
	return drops, nil
}

// AgentRoles are the agent roles of n: the members of its agents group
// named with its agent infix. Only agent roles: from Postgres 16 an admin
// with CREATEROLE is also a member of the group (ADMIN, no INHERIT), and
// must never be dropped.
func AgentRoles(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error) {
	// Plain SQL: catalog join over role memberships.
	rows, err := q.Query(ctx, `SELECT r.rolname::text FROM pg_catalog.pg_auth_members m
		JOIN pg_catalog.pg_roles r ON r.oid = m.member
		JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
		WHERE g.rolname = $1 AND pg_catalog.pg_has_role(m.member, m.roleid, 'USAGE')
		  AND starts_with(r.rolname::text, $2) ORDER BY 1`, n.Agents(), n.AgentPrefix())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// namedPolicyDrops are the DROP POLICY statements of the row-level
// security policies named after role and naming it: the guard's (attach,
// decision N12-7) and an agent's (init, after the person confirmed it,
// decision "Agent RLS").
func namedPolicyDrops(ctx context.Context, q Querier, role string) ([]string, error) {
	// Plain SQL: catalog lookup building DDL with quoted identifiers.
	rows, err := q.Query(ctx, `SELECT pg_catalog.format('DROP POLICY %I ON %s', p.polname, p.polrelid::pg_catalog.regclass)
		FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_roles r ON r.oid = ANY (p.polroles)
		WHERE p.polname = $1 AND r.rolname = $1 ORDER BY 1`, role)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// roleDrop is the SQL that drops role, or "" when it does not exist.
func roleDrop(ctx context.Context, q Querier, role string) (string, error) {
	var exists bool
	// Plain SQL: catalog lookup.
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	ident := pgx.Identifier{role}.Sanitize()
	// Plain SQL: DDL on a quoted role name. DROP OWNED BY needs the role's
	// privileges, which an admin that is not a superuser holds only through
	// an inherited membership: from Postgres 16 its automatic ADMIN grant
	// does not inherit, so take the membership first. DROP ROLE removes it.
	return "GRANT " + ident + " TO CURRENT_USER;\nDROP OWNED BY " + ident + ";\nDROP ROLE " + ident, nil
}

// agentQueryKeys are the connection string parameters the agent's
// connection string keeps from the admin's: where the server is and how
// to trust it, never who logs in. Every other parameter is dropped, among
// them user, password, passfile, service and servicefile, which pgx would
// read in place of the agent's own user and password, and sslcert, sslkey
// and sslpassword, the admin's TLS client identity (CO-9).
var agentQueryKeys = map[string]bool{
	"host":                    true,
	"port":                    true,
	"dbname":                  true,
	"sslmode":                 true,
	"sslrootcert":             true,
	"sslcrl":                  true,
	"sslcertmode":             true,
	"sslnegotiation":          true,
	"sslsni":                  true,
	"channel_binding":         true,
	"require_auth":            true,
	"target_session_attrs":    true,
	"connect_timeout":         true,
	"application_name":        true,
	"min_protocol_version":    true,
	"max_protocol_version":    true,
	"default_query_exec_mode": true,
}

// Errors for an admin connection string the agent's connection string
// cannot be built from.
// Neither repeats the string, which holds the admin password.
var (
	// ErrAdminURLForm: not a postgres:// or postgresql:// URL.
	ErrAdminURLForm = errors.New("the admin connection string must be a URL (postgres://user:password@host:port/database), not keyword/value pairs")
	// ErrAdminURLParse: a postgres:// URL that does not parse, such as a
	// Unix socket directory percent-encoded in the host.
	ErrAdminURLParse = errors.New("the admin connection URL cannot be parsed; give a Unix socket directory as a parameter (postgres://user:password@/database?host=/var/run/postgresql), not percent-encoded in the host")
)

// AgentConnString builds the agent's connection string from adminURL: its
// scheme, hosts, ports and database, the agent's user and password, and
// only the parameters in agentQueryKeys. Nothing else of the admin's
// connection string is kept, so no admin credential reaches the agent's
// credential file (CO-9). It accepts URL connection strings only
// (postgres:// or postgresql://) and refuses keyword/value strings with
// ErrAdminURLForm. Through Supabase's pooler the agent's user keeps the
// admin's project ref, so the pooler can route it.
func AgentConnString(adminURL, role, password string) (string, error) {
	if !strings.HasPrefix(adminURL, "postgres://") && !strings.HasPrefix(adminURL, "postgresql://") {
		return "", ErrAdminURLForm
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", ErrAdminURLParse
	}
	user := role
	if _, ref, ok := strings.Cut(u.User.Username(), "."); ok && supabase.PoolerHost(u.Hostname()) {
		user = role + "." + ref
	}
	query := url.Values{}
	for key, values := range u.Query() {
		if agentQueryKeys[key] {
			query[key] = values
		}
	}
	agent := url.URL{
		Scheme: u.Scheme,
		User:   url.UserPassword(user, password),
		Host:   u.Host,
		Path:   u.Path,
		// Encode writes a space as "+", which pgx reads as a plus.
		RawQuery: strings.ReplaceAll(query.Encode(), "+", "%20"),
	}
	return agent.String(), nil
}

// versionAfter is the guard's version after an install from installed that
// stops at upTo (0: this build's latest). An install never goes back.
func versionAfter(installed, upTo int) int {
	v := LatestVersion()
	if upTo > 0 {
		v = min(v, upTo)
	}
	return max(v, installed)
}

// RemoveOldInstallDoc is the page that says how to remove an older
// BasaltDB install from a database.
const RemoveOldInstallDoc = "https://github.com/BasaltDBHq/BasaltDB/blob/master/docs/remove-old-install.md"

// ErrUnusableInstall: the database has a basalt_meta this build can neither
// install over nor update: an older install (from before the guard's
// versions started again at 1, which this build cannot read), or a
// partial one. Nothing is changed for it; the person removes it first.
var ErrUnusableInstall = errors.New("basalt_meta is an older or partial BasaltDB install this build cannot use")

// CheckUsable returns ErrUnusableInstall, wrapped with what is missing,
// for a basalt_meta this build cannot install over: objects but no
// recorded version, no installs table, or an installs table without the id
// column from version 2 on. No basalt_meta, or an empty one, is usable.
// It reads the catalog and schema_version and changes nothing.
func CheckUsable(ctx context.Context, q Querier) error {
	var schema, objects, versioned, installs, installID bool
	// Plain SQL: catalog lookups, by name, needing no privilege on the schema.
	err := q.QueryRow(ctx, `
		WITH n AS (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'basalt_meta'),
		rel AS (SELECT c.oid, c.relname FROM pg_catalog.pg_class c JOIN n ON c.relnamespace = n.oid)
		SELECT EXISTS (SELECT 1 FROM n),
		       EXISTS (SELECT 1 FROM rel WHERE relname <> 'schema_version')
		         OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN n ON p.pronamespace = n.oid),
		       EXISTS (SELECT 1 FROM rel WHERE relname = 'schema_version'),
		       EXISTS (SELECT 1 FROM rel WHERE relname = 'installs'),
		       EXISTS (SELECT 1 FROM rel JOIN pg_catalog.pg_attribute a ON a.attrelid = rel.oid
		               WHERE rel.relname = 'installs' AND a.attname = 'id' AND NOT a.attisdropped)`).
		Scan(&schema, &objects, &versioned, &installs, &installID)
	if err != nil || !schema {
		return err
	}
	version := 0
	if versioned {
		if version, err = InstalledVersion(ctx, q); err != nil {
			return err
		}
	}
	switch {
	case version == 0 && objects:
		return fmt.Errorf("%w: it holds objects but no recorded version", ErrUnusableInstall)
	case version == 0:
		return nil // an empty basalt_meta: the install fills it
	case !installs:
		return fmt.Errorf("%w: version %d has no basalt_meta.installs", ErrUnusableInstall, version)
	case version >= versionInstallIDs && !installID:
		return fmt.Errorf("%w: version %d has an installs table of an older shape", ErrUnusableInstall, version)
	}
	return nil
}
