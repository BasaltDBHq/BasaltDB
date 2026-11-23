// Package setup runs a setup code as the database's admin: the checks,
// the questions, the one transaction and record_setup (CONTRACT.md, Setup
// from your laptop). The connect service, through the public package
// pkg/setup, uses it, so the setup has one implementation; pkg/setup is
// its API for other modules, without this module's internal types.
//
// It takes a connection its caller opened and reads no environment
// variable, terminal or file. Its messages name databases, hosts, roles and
// tables, never a password or a connection string's parameters.
package setup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// Refusal codes this package adds to setupcode's (setupcode.Refusal).
const (
	CodeEngineRevoked           = "ENGINE_REVOKED"
	SetuprunCodeTargetMismatch  = "TARGET_MISMATCH"
	CodeTablesMissing           = "TABLES_MISSING"
	SetuprunCodeAnswersInvalid  = "ANSWERS_INVALID"
	SetuprunCodePasskeyRequired = "PASSKEY_REQUIRED"
	SetuprunCodePasskeyInvalid  = "PASSKEY_INVALID"
	CodePasskeyMissing          = "PASSKEY_NOT_REGISTERED" //nolint:gosec // a refusal code, not a credential
	SetuprunCodeNoTables        = "NO_TABLES"
	// SetuprunCodeTablesChanged: the tables changed since they were listed.
	SetuprunCodeTablesChanged = "TABLES_CHANGED"
	// SetuprunCodeClassesChanged: a column's class stored now is not the one the
	// person saw.
	SetuprunCodeClassesChanged = "CLASSES_CHANGED"
	// SetuprunCodeSetupFailed: the database or its driver failed; nothing changed.
	SetuprunCodeSetupFailed = "SETUP_FAILED"
)

// SetuprunRefusalError is a refused setup: a code and the sentence the person reads.
// Err, when set, is the error the sentence wraps.
type SetuprunRefusalError struct {
	Code    string
	Message string
	Err     error
}

func (r *SetuprunRefusalError) Error() string { return r.Message }

func (r *SetuprunRefusalError) Unwrap() error { return r.Err }

func setuprunRefuse(code, message string) *SetuprunRefusalError {
	return &SetuprunRefusalError{Code: code, Message: message}
}

// upgradeLinePrefix starts the summary line of an UPGRADE code, replaced by
// "No guard change." when the code only records the engine.
const upgradeLinePrefix = "This upgrades Basalt's guard"

// Setup is one setup code that passed the checks needing no database.
type Setup struct {
	be      SetuprunBackend
	P       setupcode.Payload
	Names   guardmodel.Names
	ID      uuid.UUID
	Expires time.Time
	// tables are, for a code that lists schemas (listedSchemas), what
	// Prepare read from the database: the agent's write and read-only
	// tables, and those left out.
	tables guardmodel.SchemaTables
	// asInstall is an AGENT code with a verifier whose role does not
	// exist: it runs as an INSTALL (Prepare).
	asInstall bool
	// kept are, for an AGENT code that keeps the role's grants, the tables
	// the role holds a privilege on, read in Prepare: the column labels
	// cover them, and nothing is granted or revoked.
	kept []string
	// noGrants is an AGENT code that keeps the role's grants whose role
	// exists and holds none: like a dropped role, the person ticks its
	// tables (Ticked), never every table in public.
	noGrants bool
	// given: Include was called with the page's ticks (given), which
	// Prepare checks after the database's refusals; ticks: they apply
	// (Ticked), and included are those tables.
	given    *[]string
	ticks    bool
	included []string
}

// includedShape is an includedTables entry: a plain lowercase
// schema.table.
var includedShape = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$`)

// Ticked reports whether the connect page ticks tables for this code: an
// INSTALL code with agent.allTables, and an AGENT code whose role does not
// exist (it runs as an INSTALL) with agent.allTables or no tables
// (CONTRACT.md, Connect, Tables on the connect page). For an AGENT code it
// is known once Prepare found the role missing.
func (s *Setup) Ticked() bool {
	return s.listedSchemas() != nil && (s.P.Kind == setupcode.KindInstall || s.asInstall || s.noGrants)
}

// listedSchemas are the schemas whose tables Prepare lists for the agent:
// agent.allTables's, and schema public for an AGENT code that names no
// tables and whose role does not exist (the person ticks its tables, never
// every table in public); nil otherwise.
func (s *Setup) listedSchemas() []string {
	a := s.P.Agent
	switch {
	case a == nil:
		return nil
	case a.AllTables != nil:
		return a.AllTables.Schemas
	case (s.asInstall || s.noGrants) && s.P.KeepsGrants():
		return []string{publicSchema}
	}
	return nil
}

// publicSchema is the schema a dropped role's tables are ticked in.
const publicSchema = "public"

// errTicksRequired refuses to grant a listing the person did not tick: an
// AGENT code whose role does not exist and that names no tables.
func errTicksRequired(agent string) error {
	return setuprunRefuse(SetuprunCodeNoTables, fmt.Sprintf("%s has no tables in this database: tick the tables to give %s on the connect page. Nothing changed", agent, agent))
}

// Include gives Prepare the tables the person left ticked on the connect
// page. Prepare checks them after the database's own refusals (so a code
// that already ran is USED, whatever the ticks): for a code without ticks
// (Ticked false) they must be empty; for one with ticks each entry is a
// plain lowercase schema.table in a schema of agent.allTables, at most once
// (ANSWERS_INVALID otherwise), and none at all is NO_TABLES. Prepare then
// grants exactly those tables, and an entry the listing lacks is
// TABLES_CHANGED.
func (s *Setup) Include(tables []string) {
	t := slices.Clone(tables)
	s.given = &t
}

// checkIncluded applies Include's rules.
func (s *Setup) checkIncluded() error {
	if s.given == nil {
		return nil
	}
	tables := *s.given
	if !s.Ticked() {
		if len(tables) > 0 {
			return setuprunRefuse(SetuprunCodeAnswersInvalid, "this setup code names its tables, so no table can be ticked; nothing changed")
		}
		return nil
	}
	if len(tables) == 0 {
		return setuprunRefuse(SetuprunCodeNoTables, fmt.Sprintf("There is no table to give %s. Tick at least one table; nothing changed", AgentWord(s.P)))
	}
	seen := make(map[string]bool, len(tables))
	for _, t := range tables {
		schema, _, _ := strings.Cut(t, ".")
		if !includedShape.MatchString(t) || !slices.Contains(s.listedSchemas(), schema) || seen[t] {
			return setuprunRefuse(SetuprunCodeAnswersInvalid, "a ticked table is not a table of this setup's schemas, or is ticked twice; nothing changed")
		}
		seen[t] = true
	}
	s.ticks, s.included = true, slices.Clone(tables)
	return nil
}

// errTablesChanged is TABLES_CHANGED.
func errTablesChanged() error {
	return setuprunRefuse(SetuprunCodeTablesChanged, "the tables changed since they were listed (a table was dropped, renamed or given to another owner), so the setup did not run and nothing changed: check the setup again")
}

// NewSetuprun decodes code and applies the checks that need no database, in the
// contract's order (step 1): the codec, CONNECT_ONLY unless connectPage
// (the laptop command refuses a code without target before the clock
// checks; the connect service runs it), then this clock and this binary's
// guard (setupcode.CheckLocal).
func NewSetuprun(b SetuprunBackend, code string, now time.Time, connectPage bool) (*Setup, error) {
	p, err := setupcode.Decode(code)
	if err != nil {
		return nil, err
	}
	if !connectPage {
		if err := setupcode.CheckNotConnectOnly(p); err != nil {
			return nil, err
		}
	}
	if err := setupcode.CheckLocal(p, now, b.LatestVersion()); err != nil {
		return nil, err
	}
	return forPayload(b, p)
}

// forPayload is the Setup of a decoded payload, without checks.
func forPayload(b SetuprunBackend, p setupcode.Payload) (*Setup, error) {
	id, err := uuid.Parse(p.SetupID)
	if err != nil {
		return nil, err
	}
	expires, err := p.ExpiresTime()
	if err != nil {
		return nil, err
	}
	return &Setup{be: b, P: p, Names: guardmodel.Names{Prefix: p.Prefix}, ID: id, Expires: expires}, nil
}

// AgentWord names the agent in messages: its name, or "your agent" for an
// UPGRADE code.
func AgentWord(p setupcode.Payload) string {
	if p.Agent == nil {
		return "your agent"
	}
	return p.Agent.Name
}

// Spec is the agent part of the code as an install input. For a code that
// lists schemas its write tables are those Prepare read (the ticked ones);
// a recovery code whose role does not exist is an INSTALL. An AGENT code
// that names no tables keeps the role's grants.
func (s *Setup) Spec() guardmodel.AgentSpec {
	a := s.P.Agent
	write, read := a.Write, a.Read
	if s.listedSchemas() != nil {
		write, read = s.tables.Write, s.tables.ReadOnly
	}
	install := s.P.Kind == setupcode.KindInstall || s.asInstall
	change := s.P.Kind == setupcode.KindAgent && !install
	return guardmodel.AgentSpec{
		Name: a.Name, Write: write, Read: read, Verifier: a.Verifier,
		CreateOnly: install, Change: change, KeepGrants: change && s.P.KeepsGrants(),
		StatementTimeout: time.Duration(a.StatementTimeoutMs) * time.Millisecond,
	}
}

// AgentTables are the tables the agent has after the setup, in name order:
// the code's (or the ticked) tables, or for an AGENT code that keeps the
// role's grants the ones the role holds (known after Prepare).
func (s *Setup) AgentTables() []string {
	if s.P.Agent == nil {
		return nil
	}
	if s.P.KeepsGrants() && !s.asInstall && !s.noGrants {
		return slices.Clone(s.kept)
	}
	spec := s.Spec()
	out := append(slices.Clone(spec.Write), spec.Read...)
	slices.Sort(out)
	return slices.Compact(out)
}

// Tables are, for an agent.allTables code after Prepare, the tables the
// agent gets and those left out; empty otherwise.
func (s *Setup) Tables() guardmodel.SchemaTables { return s.tables }

// RunsAsInstall is whether Prepare found the role of an AGENT code with a
// verifier missing, so the setup creates it as an INSTALL does.
func (s *Setup) RunsAsInstall() bool { return s.asInstall }

// Prepared is a setup checked against the database: what it found and the
// questions the person answers before the setup runs.
type Prepared struct {
	*Setup
	Conn  *pgx.Conn
	State setupcode.SummaryState
	// Engine is what the database records about the code's engine.
	Engine SetuprunEngineState
	// EngineOnly is an UPGRADE code with nothing to upgrade that still
	// records its engine.
	EngineOnly bool
	// NothingToDo is an UPGRADE code with nothing to upgrade and no engine
	// to record: nothing runs and nothing is recorded.
	NothingToDo bool
	// Blind are the agent's tables where row-level security hides every
	// row from its role: one question each.
	Blind []guardmodel.BlindTable
}

// Prepare checks s against the database conn opens, in the contract's
// order: the target (step 3), the database's state and the engine (step
// 4), then whether an UPGRADE code has anything to do, and reads the
// row-level security questions. Every refusal leaves the database as it
// was.
func (s *Setup) Prepare(ctx context.Context, conn *pgx.Conn) (*Prepared, error) {
	if err := CheckConnTarget(s.P, conn.Config()); err != nil {
		return nil, err
	}
	q := pgquerier.Neutralize(conn)
	db, state, err := s.readDatabase(ctx, q)
	if err != nil {
		return nil, err
	}
	if err := setupcode.CheckDatabase(s.P, db); err != nil {
		return nil, err
	}
	// CheckDatabase let an AGENT code with a verifier through without its
	// role: it runs as an INSTALL, with ticks (Ticked), so it is settled
	// before the ticks are checked.
	s.asInstall = s.P.Kind == setupcode.KindAgent && s.P.HasVerifier() && len(db.Roles) == 0
	state.RunsAsInstall = s.asInstall
	if s.P.KeepsGrants() && !s.asInstall && len(db.Roles) > 0 {
		// The role's grants are the record of its tables: read them before
		// the ticks are checked, since a role with none is ticked.
		if s.kept, err = s.be.GrantedTables(ctx, q, s.P.Role()); err != nil {
			return nil, err
		}
		s.noGrants = len(s.kept) == 0
		state.NoGrants = s.noGrants
	}
	if err := s.checkIncluded(); err != nil {
		return nil, err
	}
	engine, err := s.readEngine(ctx, q)
	if err != nil {
		return nil, err
	}
	p := &Prepared{Setup: s, Conn: conn, State: state, Engine: engine}
	if UpgradeDone(s.be, s.P, state.GuardVersion) {
		p.EngineOnly = p.engineToRecord()
		p.NothingToDo = !p.EngineOnly
	}
	if p.NothingToDo || s.P.Agent == nil {
		return p, nil
	}
	if err := s.readAllTables(ctx, q, &p.State); err != nil {
		return nil, err
	}
	blind, err := s.be.AgentBlindTables(ctx, q, s.Names, s.Spec())
	if err != nil {
		return nil, MissingTablesHint(s.be, err, conn.Config().Database)
	}
	p.Blind = blind
	return p, nil
}

// readAllTables reads, for a code that lists schemas (listedSchemas), the
// tables of those schemas the admin role owns (with a primary key the
// agent's write tables, without one read only) and those left out, into s
// and the summary's state. No table at all is NO_TABLES.
func (s *Setup) readAllTables(ctx context.Context, q Querier, state *setupcode.SummaryState) error {
	if s.listedSchemas() == nil {
		return nil
	}
	tables, err := s.listAllTables(ctx, q)
	if err != nil {
		return err
	}
	if s.ticks {
		if tables, err = pickIncluded(tables, s.included); err != nil {
			return err
		}
	}
	s.tables = tables
	state.Tables, state.ReadOnly, state.Excluded = s.tables.Write, s.tables.ReadOnly, s.tables.Excluded
	return nil
}

// listAllTables lists the tables of the listed schemas (listedSchemas).
func (s *Setup) listAllTables(ctx context.Context, q Querier) (guardmodel.SchemaTables, error) {
	schemas := s.listedSchemas()
	out := guardmodel.SchemaTables{Write: []string{}, ReadOnly: []string{}}
	for _, schema := range schemas {
		got, err := s.be.AllTablesIn(ctx, q, schema)
		if err != nil {
			return guardmodel.SchemaTables{}, err
		}
		out.Write = append(out.Write, got.Write...)
		out.ReadOnly = append(out.ReadOnly, got.ReadOnly...)
		for _, e := range got.Excluded {
			out.Excluded = append(out.Excluded, setupcode.ExcludedTable{Table: e.Table, Owner: printableLabel(e.Owner)})
		}
	}
	if len(out.Write)+len(out.ReadOnly) == 0 {
		return guardmodel.SchemaTables{}, setuprunRefuse(SetuprunCodeNoTables, fmt.Sprintf("schema %s of this database has no table the admin role owns, so the agent would get nothing. "+
			"Create the tables first, or ask %s for a code that names its tables; nothing changed", strings.Join(schemas, ", "), AgentWord(s.P)))
	}
	return out, nil
}

// pickIncluded is the listing narrowed to the included tables, each with
// its access (write, or read only without a primary key); the excluded
// ones stay as listed. An included table the listing lacks is
// TABLES_CHANGED.
func pickIncluded(all guardmodel.SchemaTables, included []string) (guardmodel.SchemaTables, error) {
	out := guardmodel.SchemaTables{Write: []string{}, ReadOnly: []string{}, Excluded: all.Excluded}
	for _, t := range included {
		switch {
		case slices.Contains(all.Write, t):
			out.Write = append(out.Write, t)
		case slices.Contains(all.ReadOnly, t):
			out.ReadOnly = append(out.ReadOnly, t)
		default:
			return guardmodel.SchemaTables{}, errTablesChanged()
		}
	}
	slices.Sort(out.Write)
	slices.Sort(out.ReadOnly)
	return out, nil
}

// RecheckTables reads an agent.allTables code's tables again with q, the
// setup's own transaction (CONTRACT.md, Connect, Tables on the connect
// page), and refuses TABLES_CHANGED, nothing changed: with ticks, when a
// ticked table is gone or its access changed (a table made since is not
// included); without, when the listing is not the one Prepare read, which
// the plan grants and the person was shown. Other codes pass.
func (s *Setup) RecheckTables(ctx context.Context, q Querier) error {
	if s.listedSchemas() == nil {
		return nil
	}
	now, err := s.listAllTables(ctx, q)
	var r *SetuprunRefusalError
	if errors.As(err, &r) && r.Code == SetuprunCodeNoTables {
		return errTablesChanged() // every table went since the listing
	}
	if err != nil {
		return err
	}
	if s.ticks {
		picked, err := pickIncluded(now, s.included)
		if err != nil {
			return err
		}
		if !slices.Equal(picked.Write, s.tables.Write) || !slices.Equal(picked.ReadOnly, s.tables.ReadOnly) {
			return errTablesChanged()
		}
		return nil
	}
	if !slices.Equal(now.Write, s.tables.Write) || !slices.Equal(now.ReadOnly, s.tables.ReadOnly) || !slices.Equal(now.Excluded, s.tables.Excluded) {
		return errTablesChanged()
	}
	return nil
}

// UpgradeDone is whether an UPGRADE code has nothing to add: the installed
// guard already has every migration up to the code's guard.to (or is
// newer). No guard installed is not done: the code installs it.
func UpgradeDone(b SetuprunBackend, p setupcode.Payload, installed int) bool {
	if p.Kind != setupcode.KindUpgrade || installed == 0 {
		return false
	}
	var upTo []guardmodel.Migration
	for _, m := range b.Migrations() {
		if m.Version <= p.Guard.To {
			upTo = append(upTo, m)
		}
	}
	st := b.StatusAt(installed, upTo)
	return st.State == guardmodel.GuardOK || st.State == guardmodel.GuardNewer
}

// readDatabase reads what the checks and the summary need (step 4).
func (s *Setup) readDatabase(ctx context.Context, q Querier) (setupcode.Database, setupcode.SummaryState, error) {
	var db setupcode.Database
	var state setupcode.SummaryState
	var err error
	if db.Prefix, err = s.be.InstalledPrefix(ctx, q); err != nil {
		return db, state, err
	}
	if db.Prefix == s.Names.Prefix {
		// Another prefix is PREFIX_MISMATCH, from the checks.
		if err := s.be.CheckUsable(ctx, q); s.be.UnusableInstall(err) {
			return db, state, &SetuprunRefusalError{Code: SetuprunCodeSetupFailed, Err: err, Message: "the database has an older BasaltDB install that this version cannot use. Remove it first, then set up again: " + s.be.RemoveOldInstallDoc() + " says how. Nothing changed."}
		} else if err != nil {
			return db, state, err
		}
	}
	if state.GuardVersion, err = s.be.InstalledVersion(ctx, q); err != nil {
		return db, state, err
	}
	role := s.P.Role()
	if db.Setups, err = s.be.SetupsFor(ctx, q, s.ID, role); err != nil {
		return db, state, err
	}
	if role == "" {
		return db, state, nil
	}
	exists, err := s.be.AgentRoleExists(ctx, q, s.Names, s.P.Agent.Name)
	if err != nil || !exists {
		return db, state, err
	}
	db.Roles = []string{role}
	if s.P.Kind == setupcode.KindAgent {
		now, err := s.be.RoleStatementTimeout(ctx, q, role)
		if err != nil {
			return db, state, err
		}
		want := s.P.Agent.StatementTimeoutMs
		state.TimeoutNow = timeoutNow(now.AllDatabases, want)
		if now.ThisDatabase != "" {
			state.TimeoutThisDatabase = timeoutNow(now.ThisDatabase, want)
		}
	}
	return db, state, nil
}

// timeoutNow is the role's current statement_timeout as the summary shows
// it, or "" when it is the code's.
func timeoutNow(setting string, want int64) string {
	if setting == "" {
		return "not set"
	}
	ms, ok := settingMillis(setting)
	switch {
	case ok && ms == want:
		return ""
	case ok:
		return strconv.FormatInt(ms, 10) + " ms"
	default:
		return printableLabel(setting)
	}
}

// settingMillis reads a time setting as Postgres stores it: a number of
// milliseconds, or a number with a unit.
func settingMillis(s string) (int64, bool) {
	units := []struct {
		suffix string
		ms     int64
	}{{"ms", 1}, {"min", 60000}, {"s", 1000}, {"h", 3600000}, {"d", 86400000}, {"", 1}}
	for _, u := range units {
		num, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64); err == nil {
			return n * u.ms, true
		}
	}
	return 0, false
}

// printableLabel replaces every control character, line break and
// non-ASCII byte of text from the database with "?", so it is safe in a
// message (the rule of basalt's printableLabel).
func printableLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r >= 0x7f {
			return '?'
		}
		return r
	}, s)
}

// Summary is the summary's fixed lines for the database's state (step 5).
// An UPGRADE code that only records its engine says "No guard change."
// instead of its upgrade line.
func (p *Prepared) Summary() []string {
	lines := setupcode.Summary(p.P, p.State)
	if !p.EngineOnly {
		return lines
	}
	for i, line := range lines {
		if strings.HasPrefix(line, upgradeLinePrefix) {
			lines[i] = "No guard change."
		}
	}
	return lines
}

// RLSQuestion is the row-level security question for one table, as basalt
// init asks it.
func RLSQuestion(b guardmodel.BlindTable, agent string) string {
	return fmt.Sprintf("%s hides its rows with row-level security. Let %s see all %s of this table?", b.Table, agent, rowCount(b.Rows))
}

// rowCount is "1 row" or "n rows".
func rowCount(n int64) string {
	if n == 1 {
		return "1 row"
	}
	return fmt.Sprintf("%d rows", n)
}

// Plan builds the SQL with the person's answers (step 6): the migrations up
// to the code's guard.to, the role (taken over only when it is a plain
// agent), the grants, the policies on allRows, attach, the engine, and
// record_setup last. An answer about a table p did not ask about is
// refused.
func (p *Prepared) Plan(ctx context.Context, allRows []string) (guardmodel.Script, error) {
	policies, err := p.policies(allRows)
	if err != nil {
		return guardmodel.Script{}, err
	}
	script, err := p.plan(ctx, policies)
	if err != nil {
		return guardmodel.Script{}, MissingTablesHint(p.be, err, p.Conn.Config().Database)
	}
	return script, nil
}

func (p *Prepared) plan(ctx context.Context, policies []guardmodel.BlindTable) (guardmodel.Script, error) {
	if (p.asInstall || p.noGrants) && p.Ticked() && !p.ticks {
		// Never every table in public: only the ones the person ticked.
		return guardmodel.Script{}, errTicksRequired(p.P.Agent.Name)
	}
	opts := guardmodel.InitOptions{Names: p.Names, UpTo: p.P.Guard.To}
	agent := ""
	if p.P.Agent != nil {
		opts.Agent = p.Spec()
		opts.AgentPolicies = policies
		agent = p.P.Agent.Name
	}
	script, err := p.be.PlanInit(ctx, pgquerier.Neutralize(p.Conn), opts)
	if err != nil {
		return guardmodel.Script{}, err
	}
	record, err := p.be.RecordSetupStatement(p.Names, guardmodel.Setup{
		ID: p.ID, Kind: string(p.P.Kind), Agent: agent, GuardVersion: p.P.Guard.To, ExpiresAt: p.Expires,
	})
	if err != nil {
		return guardmodel.Script{}, err
	}
	script.Statements = append(script.Statements, p.engineStatements()...)
	script.Statements = append(script.Statements, record)
	return script, nil
}

// RefuseAnswers refuses any answer to a setup that asks nothing: an
// UPGRADE code with nothing to do.
func RefuseAnswers(allRows []string) error {
	if len(allRows) > 0 {
		return setuprunRefuse(SetuprunCodeAnswersInvalid, "the answers reply to questions this setup does not ask: it has nothing to do")
	}
	return nil
}

// policies are the blind tables the person let the agent see every row of.
func (p *Prepared) policies(allRows []string) ([]guardmodel.BlindTable, error) {
	var out []guardmodel.BlindTable
	for _, table := range allRows {
		i := blindIndex(p.Blind, table)
		if i < 0 {
			return nil, setuprunRefuse(SetuprunCodeAnswersInvalid, fmt.Sprintf("the answers name table %s, which this setup does not ask about; check the setup again", printableLabel(table)))
		}
		if blindIndex(out, table) < 0 {
			out = append(out, p.Blind[i])
		}
	}
	return out, nil
}

func blindIndex(tables []guardmodel.BlindTable, table string) int {
	for i, b := range tables {
		if b.Table == table {
			return i
		}
	}
	return -1
}

// ApplySetupWith runs script in one transaction. Its last statement is
// record_setup, run after every other one and after the coverage check, so
// the setup is recorded only with everything it sets up; any failure rolls
// all of it back. inTx, when set, runs in the same
// transaction after the migrations and the coverage check and before
// record_setup (a passkey registered with the setup). An error from it
// rolls everything back. first, when set, runs in the transaction before
// anything else (the tables read again before the grants name them).
func ApplySetupWith(ctx context.Context, b SetuprunBackend, conn *pgx.Conn, script guardmodel.Script, first, inTx func(context.Context, pgx.Tx) error) error {
	n := len(script.Statements)
	if n == 0 {
		return errors.New("nothing to run")
	}
	body, record := guardmodel.Script{Statements: script.Statements[:n-1]}, script.Statements[n-1]
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if first != nil {
			if err := first(ctx, tx); err != nil {
				return err
			}
		}
		if err := ApplyInitTx(ctx, b, pgquerier.Neutralize(tx), body); err != nil {
			return err
		}
		if inTx != nil {
			if err := inTx(ctx, tx); err != nil {
				return err
			}
		}
		if err := b.Run(ctx, pgquerier.Neutralize(tx), record.SQL); err != nil {
			return fmt.Errorf("record the setup: %w", err)
		}
		return nil
	})
	return WithGuardDetail(err)
}

// Refused turns a failed transaction into what the person reads. Nothing
// changed: the transaction rolled back. A refusal by record_setup gets the
// contract's words (USED and SUPERSEDED with the time, read again with q).
func Refused(ctx context.Context, b SetuprunBackend, q Querier, p setupcode.Payload, err error) error {
	agent := AgentWord(p)
	detail, ok := b.SetupRefusal(err)
	if !ok {
		return NothingChanged(WithGuardDetail(err))
	}
	switch setupcode.Refusal(detail) {
	case setupcode.RefusalUsed, setupcode.RefusalSuperseded:
		if s, serr := forPayload(b, p); serr == nil {
			if db, _, rerr := s.readDatabase(ctx, q); rerr == nil {
				if cerr := setupcode.CheckDatabase(p, db); cerr != nil {
					return cerr
				}
			}
		}
		return &SetuprunRefusalError{Code: detail, Err: err, Message: fmt.Sprintf("the database refused this setup code (%s): it, or a newer one for %s, already ran. Ask %s for a new one", detail, agent, agent)}
	case setupcode.RefusalExpired:
		expires, _ := p.ExpiresTime() // the code passed Decode, so it parses
		return &SetuprunRefusalError{Code: detail, Err: err, Message: fmt.Sprintf("this setup code expired on %s by the database's clock. Ask %s for a new one", expires.UTC().Format("2006-01-02 15:04 UTC"), agent)}
	default:
		return &SetuprunRefusalError{Code: detail, Err: err, Message: fmt.Sprintf("the database's clock refuses this setup code (%s): check the database's and this computer's clocks, or ask %s for a new code", detail, agent)}
	}
}

// RLSBlindWarnings are the warnings about every write and read table where
// row-level security still hides all rows from the agent role: Supabase
// can turn RLS on for new tables, and the agent then reads 0 rows without
// any error. A failed check is a warning too: the guard is installed
// either way.
func RLSBlindWarnings(ctx context.Context, b SetuprunBackend, q Querier, role string, spec guardmodel.AgentSpec) []string {
	tables := append(append([]string{}, spec.Write...), spec.Read...)
	if len(tables) == 0 {
		return nil // no tables would check every table the role can SELECT
	}
	blind, err := b.RLSBlindTables(ctx, q, role, tables)
	if err != nil {
		return []string{fmt.Sprintf("could not check row-level security on the agent's tables: %v", err)}
	}
	out := make([]string, 0, len(blind))
	for _, t := range blind {
		out = append(out, fmt.Sprintf("row-level security is on for %s and no policy lets %s see rows; "+
			"the agent will read 0 rows. Add a policy for that role, or disable RLS on the table.", t, role))
	}
	return out
}

// sqlUndefinedTable is Postgres's undefined_table: a guard older than the
// table, or none.
const sqlUndefinedTable = "42P01"

func isUndefinedTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == sqlUndefinedTable
}
