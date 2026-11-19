// Package setuprun runs a setup code as the database's admin: the checks,
// the questions, the one transaction and record_setup (CONTRACT.md, Setup
// from your laptop). basalt init --setup-code and the public package
// pkg/setup share it, so the setup has one implementation; pkg/setup is
// its API for other modules, without this module's internal types.
//
// It takes a connection its caller opened and reads no environment
// variable, terminal or file. Its messages name databases, hosts, roles and
// tables, never a password or a connection string's parameters.
package setuprun

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engineaddr"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// Refusal codes this package adds to setupcode's (setupcode.Refusal).
const (
	CodeEngineURLInvalid = "ENGINE_URL_INVALID"
	CodeEngineKeyMissing = "ENGINE_KEY_MISSING"
	CodeEngineRevoked    = "ENGINE_REVOKED"
	CodeTargetMismatch   = "TARGET_MISMATCH"
	CodeTablesMissing    = "TABLES_MISSING"
	CodeUnknownAnswer    = "UNKNOWN_ANSWER"
	CodePasskeyMissing   = "PASSKEY_NOT_REGISTERED" //nolint:gosec // a refusal code, not a credential
)

// RefusalError is a refused setup: a code and the sentence the person reads.
// Err, when set, is the error the sentence wraps.
type RefusalError struct {
	Code    string
	Message string
	Err     error
}

func (r *RefusalError) Error() string { return r.Message }

func (r *RefusalError) Unwrap() error { return r.Err }

func refuse(code, message string) *RefusalError { return &RefusalError{Code: code, Message: message} }

// upgradeLinePrefix starts the summary line of an UPGRADE code, replaced by
// "No guard change." when the code only records the engine.
const upgradeLinePrefix = "This upgrades Basalt's guard"

// Setup is one setup code that passed the checks needing no database.
type Setup struct {
	P       setupcode.Payload
	Names   guard.Names
	ID      uuid.UUID
	Expires time.Time
	// EngineURL is the address to record with the code's engine key, in
	// its written form; "" when none was given.
	EngineURL string
}

// New decodes code and applies the checks that need no database, in the
// contract's order (step 1): the engine address's rules, the codec, this
// clock and this binary's guard (setupcode.CheckLocal), then
// ENGINE_KEY_MISSING.
func New(code string, now time.Time, engineURL string) (*Setup, error) {
	if engineURL != "" {
		u, err := engineaddr.Parse(engineURL)
		if err != nil {
			return nil, &RefusalError{Code: CodeEngineURLInvalid, Message: "the engine address: " + err.Error(), Err: err}
		}
		engineURL = u
	}
	p, err := setupcode.Decode(code)
	if err != nil {
		return nil, err
	}
	if err := setupcode.CheckLocal(p, now, guard.LatestVersion()); err != nil {
		return nil, err
	}
	if engineURL != "" && p.Engine == nil {
		return nil, refuse(CodeEngineKeyMissing, fmt.Sprintf("ENGINE_KEY_MISSING: this setup code carries no engine key, so basalt cannot record the engine address. "+
			"Ask %s to check basalt status (its key file may be refused) and make a new code", AgentWord(p)))
	}
	s, err := forPayload(p)
	if err != nil {
		return nil, err
	}
	s.EngineURL = engineURL
	return s, nil
}

// forPayload is the Setup of a decoded payload, without checks.
func forPayload(p setupcode.Payload) (*Setup, error) {
	id, err := uuid.Parse(p.SetupID)
	if err != nil {
		return nil, err
	}
	expires, err := p.ExpiresTime()
	if err != nil {
		return nil, err
	}
	return &Setup{P: p, Names: guard.Names{Prefix: p.Prefix}, ID: id, Expires: expires}, nil
}

// AgentWord names the agent in messages: its name, or "your agent" for an
// UPGRADE code.
func AgentWord(p setupcode.Payload) string {
	if p.Agent == nil {
		return "your agent"
	}
	return p.Agent.Name
}

// Spec is the agent part of the code as an install input.
func (s *Setup) Spec() guard.AgentSpec {
	a := s.P.Agent
	return guard.AgentSpec{
		Name: a.Name, Write: a.Write, Read: a.Read, Verifier: a.Verifier,
		CreateOnly: s.P.Kind == setupcode.KindInstall, Change: s.P.Kind == setupcode.KindAgent,
		StatementTimeout: time.Duration(a.StatementTimeoutMs) * time.Millisecond,
	}
}

// Prepared is a setup checked against the database: what it found and the
// questions the person answers before the setup runs.
type Prepared struct {
	*Setup
	Conn  *pgx.Conn
	State setupcode.SummaryState
	// Engine is what the database records about the code's engine.
	Engine EngineState
	// EngineOnly is an UPGRADE code with nothing to upgrade that still
	// records its engine.
	EngineOnly bool
	// NothingToDo is an UPGRADE code with nothing to upgrade and no engine
	// to record: nothing runs and nothing is recorded.
	NothingToDo bool
	// Blind are the agent's tables where row-level security hides every
	// row from its role: one question each.
	Blind []guard.BlindTable
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
	db, state, err := s.readDatabase(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := setupcode.CheckDatabase(s.P, db); err != nil {
		return nil, err
	}
	engine, err := s.readEngine(ctx, conn)
	if err != nil {
		return nil, err
	}
	p := &Prepared{Setup: s, Conn: conn, State: state, Engine: engine}
	if UpgradeDone(s.P, state.GuardVersion) {
		p.EngineOnly = p.engineToRecord()
		p.NothingToDo = !p.EngineOnly
	}
	if p.NothingToDo || s.P.Agent == nil {
		return p, nil
	}
	blind, err := guard.AgentBlindTables(ctx, conn, s.Names, s.Spec())
	if err != nil {
		return nil, MissingTablesHint(err, conn.Config().Database)
	}
	p.Blind = blind
	return p, nil
}

// UpgradeDone is whether an UPGRADE code has nothing to add: the installed
// guard already has every migration up to the code's guard.to (or is
// newer). No guard installed is not done: the code installs it.
func UpgradeDone(p setupcode.Payload, installed int) bool {
	if p.Kind != setupcode.KindUpgrade || installed == 0 {
		return false
	}
	var upTo []guard.Migration
	for _, m := range guard.Migrations() {
		if m.Version <= p.Guard.To {
			upTo = append(upTo, m)
		}
	}
	st := guard.StatusAt(installed, upTo)
	return st.State == guard.GuardOK || st.State == guard.GuardNewer
}

// readDatabase reads what the checks and the summary need (step 4).
func (s *Setup) readDatabase(ctx context.Context, q guard.Querier) (setupcode.Database, setupcode.SummaryState, error) {
	var db setupcode.Database
	var state setupcode.SummaryState
	var err error
	if db.Prefix, err = guard.InstalledPrefix(ctx, q); err != nil {
		return db, state, err
	}
	if state.GuardVersion, err = guard.InstalledVersion(ctx, q); err != nil {
		return db, state, err
	}
	role := s.P.Role()
	if db.Setups, err = guard.SetupsFor(ctx, q, s.ID, role); err != nil {
		return db, state, err
	}
	if role == "" {
		return db, state, nil
	}
	exists, err := guard.AgentRoleExists(ctx, q, s.Names, s.P.Agent.Name)
	if err != nil || !exists {
		return db, state, err
	}
	db.Roles = []string{role}
	if s.P.Kind == setupcode.KindAgent {
		now, err := guard.RoleStatementTimeout(ctx, q, role)
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
func RLSQuestion(b guard.BlindTable, agent string) string {
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
// agent), the grants, the policies on allRows, attach, the engine and the
// engines to revoke, and record_setup last. An answer about a table or an
// engine p did not ask about is refused.
func (p *Prepared) Plan(ctx context.Context, allRows, revoke []string) (guard.Script, error) {
	policies, err := p.policies(allRows)
	if err != nil {
		return guard.Script{}, err
	}
	if err := p.checkRevoke(revoke); err != nil {
		return guard.Script{}, err
	}
	script, err := p.plan(ctx, policies, revoke)
	if err != nil {
		return guard.Script{}, MissingTablesHint(err, p.Conn.Config().Database)
	}
	return script, nil
}

func (p *Prepared) plan(ctx context.Context, policies []guard.BlindTable, revoke []string) (guard.Script, error) {
	opts := guard.InitOptions{Names: p.Names, UpTo: p.P.Guard.To}
	agent := ""
	if p.P.Agent != nil {
		opts.Agent = p.Spec()
		opts.AgentPolicies = policies
		agent = p.P.Agent.Name
	}
	script, err := guard.PlanInit(ctx, p.Conn, opts)
	if err != nil {
		return guard.Script{}, err
	}
	record, err := guard.RecordSetupStatement(p.Names, guard.Setup{
		ID: p.ID, Kind: string(p.P.Kind), Agent: agent, GuardVersion: p.P.Guard.To, ExpiresAt: p.Expires,
	})
	if err != nil {
		return guard.Script{}, err
	}
	script.Statements = append(script.Statements, p.engineStatements(revoke)...)
	script.Statements = append(script.Statements, record)
	return script, nil
}

// policies are the blind tables the person let the agent see every row of.
func (p *Prepared) policies(allRows []string) ([]guard.BlindTable, error) {
	var out []guard.BlindTable
	for _, table := range allRows {
		i := blindIndex(p.Blind, table)
		if i < 0 {
			return nil, refuse(CodeUnknownAnswer, fmt.Sprintf("the answers name table %s, which this setup does not ask about; check the setup again", printableLabel(table)))
		}
		if blindIndex(out, table) < 0 {
			out = append(out, p.Blind[i])
		}
	}
	return out, nil
}

func blindIndex(tables []guard.BlindTable, table string) int {
	for i, b := range tables {
		if b.Table == table {
			return i
		}
	}
	return -1
}

// ApplySetup runs script in one transaction. Its last statement is
// record_setup, run after every other one and after the coverage check, so
// the setup is recorded only with everything it sets up; any failure rolls
// all of it back.
func ApplySetup(ctx context.Context, conn *pgx.Conn, script guard.Script) error {
	n := len(script.Statements)
	if n == 0 {
		return errors.New("nothing to run")
	}
	return ApplyInit(ctx, conn, guard.Script{Statements: script.Statements[:n-1]}, script.Statements[n-1])
}

// Refused turns a failed transaction into what the person reads. Nothing
// changed: the transaction rolled back. A refusal by record_setup gets the
// contract's words (USED and SUPERSEDED with the time, read again with q).
func Refused(ctx context.Context, q guard.Querier, p setupcode.Payload, err error) error {
	agent := AgentWord(p)
	detail, ok := guard.SetupRefusal(err)
	if !ok {
		return NothingChanged(WithGuardDetail(err))
	}
	switch setupcode.Refusal(detail) {
	case setupcode.RefusalUsed, setupcode.RefusalSuperseded:
		if s, serr := forPayload(p); serr == nil {
			if db, _, rerr := s.readDatabase(ctx, q); rerr == nil {
				if cerr := setupcode.CheckDatabase(p, db); cerr != nil {
					return cerr
				}
			}
		}
		return &RefusalError{Code: detail, Err: err, Message: fmt.Sprintf("the database refused this setup code (%s): it, or a newer one for %s, already ran. Ask %s for a new one", detail, agent, agent)}
	case setupcode.RefusalExpired:
		expires, _ := p.ExpiresTime() // the code passed Decode, so it parses
		return &RefusalError{Code: detail, Err: err, Message: fmt.Sprintf("this setup code expired on %s by the database's clock. Ask %s for a new one", expires.UTC().Format("2006-01-02 15:04 UTC"), agent)}
	default:
		return &RefusalError{Code: detail, Err: err, Message: fmt.Sprintf("the database's clock refuses this setup code (%s): check the database's and this computer's clocks, or ask %s for a new code", detail, agent)}
	}
}

// RLSBlindWarnings are the warnings about every write and read table where
// row-level security still hides all rows from the agent role: Supabase
// can turn RLS on for new tables, and the agent then reads 0 rows without
// any error. A failed check is a warning too: the guard is installed
// either way.
func RLSBlindWarnings(ctx context.Context, q guard.Querier, role string, spec guard.AgentSpec) []string {
	tables := append(append([]string{}, spec.Write...), spec.Read...)
	blind, err := guard.RLSBlindTables(ctx, q, role, tables)
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
