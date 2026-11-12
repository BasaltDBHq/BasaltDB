package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the part of a pgx connection, pool or transaction this
// package needs.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const (
	// passwordBytes of randomness in a generated agent password (hex encoded).
	passwordBytes = 32
	// DefaultStatementTimeout is the agent role's query time limit.
	DefaultStatementTimeout = 30 * time.Second
	redacted                = "********"
)

// ErrInvalidAgent is returned for an agent spec that cannot be installed.
var ErrInvalidAgent = errors.New("invalid agent")

// AgentSpec is one agent role and the tables it may use. Tables are
// "schema.table" or "table" (schema public).
type AgentSpec struct {
	Name string
	// Password is the hex password to set (NewPassword). Empty keeps the
	// password of a role that exists (AE-12); see AgentRoleExists.
	Password string
	// Verifier is the password as a SCRAM-SHA-256 verifier (a setup code,
	// checked by CheckVerifier), set in place of Password, which stays
	// empty. The person reads it in the SQL: it lets nobody log in.
	Verifier string
	// CreateOnly creates the role with a plain CREATE ROLE, which Postgres
	// refuses when the role exists (an INSTALL setup code). Without it a
	// Verifier is set on the existing role with ALTER ROLE, which Postgres
	// refuses when the role does not exist (an AGENT setup code). Needs
	// Password or Verifier.
	CreateOnly       bool
	Read             []string
	Write            []string
	StatementTimeout time.Duration
}

// InitOptions configures PlanInit. Agent is optional: an empty Name
// installs or upgrades basalt_meta only.
type InitOptions struct {
	Names Names
	Agent AgentSpec
	// AgentPolicies are the agent's tables the person confirmed the agent
	// may see every row of (from AgentBlindTables). Each gets a policy
	// named after the agent role and a ledger row; nothing else does.
	AgentPolicies []BlindTable
}

// Statement is one step of a Script. Shown is what the person sees when it
// differs from SQL (a password redacted).
type Statement struct {
	SQL   string
	Shown string
}

// Script is the ordered SQL basalt init runs, in one transaction.
type Script struct {
	Statements []Statement
}

// SQL renders the script for the person to read, secrets redacted.
func (s Script) SQL() string {
	parts := make([]string, 0, len(s.Statements))
	for _, st := range s.Statements {
		text := st.SQL
		if st.Shown != "" {
			text = st.Shown
		}
		parts = append(parts, strings.TrimSpace(text))
	}
	return strings.Join(parts, "\n\n") + "\n"
}

// Apply runs the script on tx. The caller commits.
func (s Script) Apply(ctx context.Context, tx pgx.Tx) error {
	for i, st := range s.Statements {
		if _, err := tx.Exec(ctx, st.SQL); err != nil {
			return fmt.Errorf("init step %d: %w", i+1, err)
		}
	}
	return nil
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
func PlanInit(ctx context.Context, q Querier, opts InitOptions) (Script, error) {
	n := opts.Names
	if err := n.Validate(); err != nil {
		return Script{}, err
	}
	// Before anything else, so a missing table fails init with one message.
	if err := checkTablesExist(ctx, q, opts.Agent); err != nil {
		return Script{}, err
	}
	version, err := InstalledVersion(ctx, q)
	if err != nil {
		return Script{}, err
	}
	var s Script
	add := func(sql string) { s.Statements = append(s.Statements, Statement{SQL: n.render(sql)}) }
	add(installRoles)
	add(installSchema)
	for _, m := range migrations {
		if m.version <= version {
			continue
		}
		add(migrationBegin + m.sql + fmt.Sprintf(migrationEnd, m.version))
	}
	if opts.Agent.Name != "" {
		agent, err := planAgent(ctx, q, n, opts.Agent)
		if err != nil {
			return Script{}, err
		}
		s.Statements = append(s.Statements, agent...)
		role, err := n.Agent(opts.Agent.Name)
		if err != nil {
			return Script{}, err
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
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{guard}}') THEN
        CREATE ROLE {{guard}} NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{agents}}') THEN
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
SET LOCAL search_path = pg_catalog;
` + schemaVersionTable

const migrationEnd = `
INSERT INTO basalt_meta.schema_version (version) VALUES (%d);
RESET search_path;
RESET ROLE;`

const attachAll = `
SELECT count(1) FROM basalt_meta.attach_all();`

func planAgent(ctx context.Context, q Querier, n Names, spec AgentSpec) ([]Statement, error) {
	role, err := n.Agent(spec.Name)
	if err != nil {
		return nil, err
	}
	if err := checkAgentPassword(spec); err != nil {
		return nil, err
	}
	timeout := spec.StatementTimeout
	if timeout <= 0 {
		timeout = DefaultStatementTimeout
	}
	grants, err := planGrants(ctx, q, role, spec)
	if err != nil {
		return nil, err
	}
	return append([]Statement{agentRoleStatement(n, role, spec, timeout.Milliseconds())}, grants...), nil
}

// checkAgentPassword accepts at most one of a generated password and a
// verifier, and CreateOnly only with one of them.
func checkAgentPassword(spec AgentSpec) error {
	switch {
	case spec.Password != "" && spec.Verifier != "":
		return fmt.Errorf("%w: give a password or a verifier, not both", ErrInvalidAgent)
	case spec.Password != "" && !isHex(spec.Password):
		return fmt.Errorf("%w: password must be generated by NewPassword", ErrInvalidAgent)
	case spec.Verifier != "":
		return CheckVerifier(spec.Verifier)
	case spec.CreateOnly && spec.Password == "":
		return fmt.Errorf("%w: a new role needs a password or a verifier", ErrInvalidAgent)
	}
	return nil
}

// agentRoleStatement creates, rotates or keeps the agent role's password.
// A generated password is redacted in what the person sees; a verifier is
// shown as is.
func agentRoleStatement(n Names, role string, spec AgentSpec, timeoutMs int64) Statement {
	render := func(tmpl, password string) string { return n.render(fmt.Sprintf(tmpl, role, password, timeoutMs)) }
	switch {
	case spec.Verifier != "" && spec.CreateOnly:
		return Statement{SQL: render(agentCreateRoleSQL, quoteLiteral(spec.Verifier))}
	case spec.Verifier != "":
		return Statement{SQL: render(agentAlterRoleSQL, quoteLiteral(spec.Verifier))}
	case spec.CreateOnly:
		return Statement{SQL: render(agentCreateRoleSQL, quoteLiteral(spec.Password)),
			Shown: render(agentCreateRoleSQL, quoteLiteral(redacted))}
	case spec.Password != "":
		return Statement{SQL: render(agentRoleSQL, spec.Password), Shown: render(agentRoleSQL, redacted)}
	}
	return Statement{SQL: n.render(fmt.Sprintf(agentKeepRoleSQL, role, timeoutMs))}
}

// quoteLiteral renders s as a SQL string literal (standard_conforming_strings).
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// AgentRoleExists reports whether the agent's role exists, so init can keep
// its password.
func AgentRoleExists(ctx context.Context, q Querier, n Names, agent string) (bool, error) {
	role, err := n.Agent(agent)
	if err != nil {
		return false, err
	}
	query, args, err := sq.Select("1").Prefix("SELECT EXISTS (").From("pg_roles").
		Where(sq.Eq{"rolname": role}).Suffix(")").PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return false, err
	}
	var exists bool
	err = q.QueryRow(ctx, query, args...).Scan(&exists)
	return exists, err
}

// agentKeepRoleSQL updates an agent role that exists without touching its
// password. %[1]s is the validated role, %[2]d the statement timeout in ms.
const agentKeepRoleSQL = `
ALTER ROLE %[1]s LOGIN;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[2]d;`

// agentRoleSQL creates or rotates one agent role. %[1]s is the validated
// role, %[2]s the hex password, %[3]d the statement timeout in ms.
const agentRoleSQL = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
        CREATE ROLE %[1]s LOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%[2]s';
    ELSE
        ALTER ROLE %[1]s LOGIN PASSWORD '%[2]s';
    END IF;
END $$;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;`

// agentCreateRoleSQL creates a new agent role with a plain CREATE ROLE, so
// a role that exists is refused (an INSTALL setup code never takes over a
// role). %[1]s is the validated role, %[2]s the password or verifier as a
// SQL literal, %[3]d the statement timeout in ms.
const agentCreateRoleSQL = `
CREATE ROLE %[1]s LOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %[2]s;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;`

// agentAlterRoleSQL sets the password of an agent role that exists; a
// role that does not exist is refused. Arguments as agentCreateRoleSQL.
// The password comes from whoever made the setup code, so this must never
// reach a role that is not a plain agent: it refuses (BS008) a role with
// elevated attributes or outside the agents group itself, and record_setup,
// run in the same transaction, refuses a superuser again.
const agentAlterRoleSQL = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.rolname = '%[1]s' AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
              OR r.rolreplication OR r.rolbypassrls)
          AND pg_catalog.pg_has_role(r.oid, '{{agents}}', 'USAGE'))
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = '%[1]s') THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = '%[1]s is not a plain agent role: a setup code cannot set its password';
    END IF;
END $$;
ALTER ROLE %[1]s LOGIN PASSWORD %[2]s;
GRANT {{agents}} TO %[1]s;
ALTER ROLE %[1]s SET statement_timeout = %[3]d;`

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
		return tableRef{}, fmt.Errorf("%w: table %q must be schema.table", ErrInvalidAgent, s)
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
func checkTablesExist(ctx context.Context, q Querier, spec AgentSpec) error {
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

func planGrants(ctx context.Context, q Querier, role string, spec AgentSpec) ([]Statement, error) {
	ident := pgx.Identifier{role}.Sanitize()
	var out []Statement
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
			out = append(out, Statement{SQL: sql})
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

// Uninstall drops the guard's and agents' RLS policies and basalt_meta (and with it
// every guard trigger), then the agent roles, the group and the owner.
// Roles are cluster objects that
// DROP SCHEMA leaves behind; DROP OWNED BY revokes their grants in this
// database. A role with privileges in another database fails to drop.
func Uninstall(ctx context.Context, q Querier, n Names) error {
	if err := n.Validate(); err != nil {
		return err
	}
	// Plain SQL: catalog join over role memberships. Only agent roles: from
	// Postgres 16 an admin with CREATEROLE is also a member of the group
	// (ADMIN, no INHERIT), and must never be dropped.
	rows, err := q.Query(ctx, `SELECT r.rolname::text FROM pg_catalog.pg_auth_members m
		JOIN pg_catalog.pg_roles r ON r.oid = m.member
		JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
		WHERE g.rolname = $1 AND pg_catalog.pg_has_role(m.member, m.roleid, 'USAGE')
		  AND starts_with(r.rolname::text, $2) ORDER BY 1`, n.Agents(), n.Prefix+agentInfix)
	if err != nil {
		return err
	}
	agents, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, role := range append(agents, n.Guard()) {
		if err := dropNamedPolicies(ctx, q, role); err != nil {
			return err
		}
	}
	// Plain SQL: DDL.
	if _, err := q.Exec(ctx, `DROP SCHEMA IF EXISTS basalt_meta CASCADE`); err != nil {
		return err
	}
	for _, role := range append(agents, n.Agents(), n.Guard()) {
		if err := dropRole(ctx, q, role); err != nil {
			return err
		}
	}
	return nil
}

// dropNamedPolicies drops the row-level security policies named after role
// and naming it: the guard's (attach, decision N12-7) and an agent's (init,
// after the person confirmed it, decision "Agent RLS").
func dropNamedPolicies(ctx context.Context, q Querier, role string) error {
	// Plain SQL: catalog lookup building DDL with quoted identifiers.
	rows, err := q.Query(ctx, `SELECT format('DROP POLICY %I ON %s', p.polname, p.polrelid::regclass)
		FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_roles r ON r.oid = ANY (p.polroles)
		WHERE p.polname = $1 AND r.rolname = $1 ORDER BY 1`, role)
	if err != nil {
		return err
	}
	drops, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, sql := range drops {
		if _, err := q.Exec(ctx, sql); err != nil {
			return fmt.Errorf("drop policy of %s: %w", role, err)
		}
	}
	return nil
}

func dropRole(ctx context.Context, q Querier, role string) error {
	var exists bool
	// Plain SQL: catalog lookup.
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	ident := pgx.Identifier{role}.Sanitize()
	// Plain SQL: DDL on a quoted role name. DROP OWNED BY needs the role's
	// privileges, which an admin that is not a superuser holds only through
	// an inherited membership: from Postgres 16 its automatic ADMIN grant
	// does not inherit, so take the membership first. DROP ROLE removes it.
	if _, err := q.Exec(ctx, "GRANT "+ident+" TO CURRENT_USER;\nDROP OWNED BY "+ident+";\nDROP ROLE "+ident); err != nil {
		return fmt.Errorf("drop role %s: %w", role, err)
	}
	return nil
}

// supabasePoolerHost is the host suffix of Supabase's pooler (Supavisor),
// which routes a connection by the project ref after the role name:
// user "postgres.<ref>" logs in as role postgres of project <ref>.
const supabasePoolerHost = ".pooler.supabase.com"

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
	if _, ref, ok := strings.Cut(u.User.Username(), "."); ok && strings.HasSuffix(u.Hostname(), supabasePoolerHost) {
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
