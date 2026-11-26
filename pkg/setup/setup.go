// Package setup runs a Basalt setup code against a person's database, as
// the removed laptop command did on their own computer (CONTRACT.md, The
// setup checks), for a program other than the basalt CLI.
//
// Three steps match a page that runs a setup:
//
//   - Describe needs no database: the code and a clock in, what the code
//     asks for and its fingerprint out, or a refusal.
//   - Check takes an open admin connection: a refusal out, or the questions
//     to ask the person and whether a passkey is needed.
//   - Run takes the connection, the answers and, when needed, the person's
//     verified passkey, and runs the setup in one transaction.
//
// Run stands alone: nothing makes a caller call Describe or Check first, so
// Run repeats every refusal of both, in the same order, computes the
// questions itself and refuses an answer to a question it did not compute.
//
// The package takes a connection its caller opened as the database's admin.
// It reads no environment variable, terminal or file. Its messages name
// databases, hosts, roles and tables, never a connection string. An
// Error's Message never carries the database's or the driver's own words
// (see Error). A caller behind a transaction pooler opens the connection
// with pgx.QueryExecModeExec, as basalt does.
package setup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// Request is what every step is given.
type Request struct {
	// Code is the setup code (basalt-setup.1....). Whitespace in it is
	// ignored, so a wrapped copy works.
	Code string
	// Now is the clock the code's times are checked against.
	Now time.Time
	// ConnectPage accepts a connect-only code (no target), which only the
	// connect service runs, with the database of the connection it opened.
	// Unset, such a code is refused CONNECT_ONLY first, as the laptop
	// command refuses it.
	ConnectPage bool
	// Included are the tables the person left ticked on the connect page
	// (CONTRACT.md, Connect, Tables on the connect page); nil is no ticks
	// (the laptop command, and CheckSetup, which lists every table). The
	// connect page ticks tables of an INSTALL code with agent.allTables:
	// Check and Run then cover exactly the included tables (their
	// questions, columns and grants), an entry the listing lacks is
	// TABLES_CHANGED, and none at all is NO_TABLES. For any other code its
	// Tables must be empty (ANSWERS_INVALID). Run with ConnectPage refuses
	// such a code without Included, NO_TABLES.
	Included *Included
}

// Included are the tables ticked on the connect page.
type Included struct {
	// Tables are schema.table, each a plain lowercase name in a schema of
	// agent.allTables, at most once.
	Tables []string
}

// Kind is what a setup code does.
type Kind string

// Kinds.
const (
	// KindInstall installs the guard and creates a new agent role.
	KindInstall Kind = "INSTALL"
	// KindAgent changes an existing agent's tables, and its password when
	// the code carries a verifier.
	KindAgent Kind = "AGENT"
	// KindUpgrade upgrades the guard only.
	KindUpgrade Kind = "UPGRADE"
)

// Target is the database the code's agent connects to.
type Target struct {
	Host     string
	Port     int
	Database string
	// SupabaseRef is the Supabase project's ref when the agent's connection
	// names one, else "".
	SupabaseRef string
}

// Description is what a setup code asks for.
type Description struct {
	SetupID string
	Kind    Kind
	// Agent is the agent's name, "" for an UPGRADE code.
	Agent string
	// AgentWord names the agent in messages: its name, or "your agent".
	AgentWord string
	// AgentRole is the agent's database role, "" for an UPGRADE code.
	AgentRole string
	Prefix    string
	// Target is the database the code's agent connects to; nil for a
	// connect-only code, whose database is the one the connection names.
	Target    *Target
	GuardFrom int
	GuardTo   int
	// Write and Read are the agent's tables (schema.table), empty with
	// AllTablesSchemas. Both empty without AllTablesSchemas is an AGENT
	// code that keeps the role's current grants (KeepsGrants).
	Write []string
	Read  []string
	// AllTablesSchemas are, for an agent.allTables code, the schemas whose
	// tables the agent gets (Check lists them); nil otherwise.
	AllTablesSchemas []string
	// KeepsGrants is an AGENT code that names no tables: the role keeps
	// the grants it holds, and the setup grants and revokes none. When the
	// role does not exist, Check lists schema public and the person ticks
	// the tables (Checked.Ticked).
	KeepsGrants bool
	// StatementTimeoutMs is the agent role's statement timeout, 0 for an
	// UPGRADE code.
	StatementTimeoutMs int64
	ExpiresAt          time.Time
	// Fingerprint is the setup fingerprint the person compares with their
	// agent's.
	Fingerprint string
	// EngineFingerprint is the fingerprint of the code's engine key, ""
	// when the code carries none.
	EngineFingerprint string
	// EngineKey is the code's engine key as it carries it (SPKI DER,
	// base64url): the key a connect-only setup's CollectAddress must be
	// signed with. "" when the code carries none.
	EngineKey string
	// TrustPin is the SHA-256 (DER, lowercase hex) of the certificate the
	// bot's engine has pinned for the target's host, "" when the code
	// carries none: a hint for the connect page's trust step, never trust.
	TrustPin string
	// Summary is the summary's fixed lines, without the database's state:
	// an UPGRADE code's line names the guard version the code was made
	// against. Check's Summary is the one to show before running.
	Summary []string
}

// store is the database side this package hands the setup service: pkg/setup
// is the second composition root, for a program that calls it directly.
var store = setupstore.New()

// Describe decodes the code and applies the checks that need no database,
// in the contract's order: the codec
// (NOT_A_SETUP_CODE, UNSUPPORTED_FORMAT, DAMAGED, INVALID), the clock
// (EXPIRED, SETUP_ID_IN_FUTURE, EXPIRY_TOO_FAR), this build's guard
// (BINARY_TOO_OLD, GUARD_TOO_OLD). A refusal is an *Error.
func Describe(req Request) (Description, error) {
	s, err := setuprun.NewSetuprun(store, req.Code, req.Now, req.ConnectPage)
	if err != nil {
		return Description{}, asError(err)
	}
	return describe(s), nil
}

func describe(s *setuprun.Setup) Description {
	p := s.P
	d := Description{
		SetupID: p.SetupID, Kind: Kind(p.Kind), AgentWord: setuprun.AgentWord(p), AgentRole: p.Role(), Prefix: p.Prefix,
		GuardFrom: p.Guard.From, GuardTo: p.Guard.To, ExpiresAt: s.Expires, Fingerprint: p.Fingerprint(),
		Summary:  setupcode.Summary(p, setupcode.SummaryState{GuardVersion: p.Guard.From}),
		TrustPin: p.TrustPin,
	}
	if t := p.Target; t != nil {
		d.Target = &Target{Host: t.Host, Port: t.Port, Database: t.Database, SupabaseRef: t.SupabaseRef}
	}
	if a := p.Agent; a != nil {
		d.Agent, d.StatementTimeoutMs = a.Name, a.StatementTimeoutMs
		d.Write, d.Read = slices.Clone(a.Write), slices.Clone(a.Read)
		if a.AllTables != nil {
			d.AllTablesSchemas = slices.Clone(a.AllTables.Schemas)
		}
		d.KeepsGrants = p.KeepsGrants()
	}
	if p.Engine != nil {
		d.EngineKey = p.Engine.PublicKey
		// Decode checked the key: it parses.
		if key, err := p.Engine.Key(); err == nil {
			d.EngineFingerprint = channel.FingerprintOf(channel.EngineIDOf(key))
		}
	}
	return d
}

// Checked is a setup code checked against the database.
type Checked struct {
	Description Description
	// NothingToDo is set for an UPGRADE code the database's guard already
	// has, with no engine to record: Run runs nothing and records nothing.
	// The rest of Checked is then empty.
	NothingToDo *NothingToDo
	// Summary is the summary's fixed lines for the database's state, to
	// show before the person approves.
	Summary []string
	// EngineLines follow the summary when the code carries an engine key.
	EngineLines []string
	Questions   Questions
	// PasskeyNeeded is whether the database has no active portal passkey:
	// Run then needs the person's (RunInput.Passkey).
	PasskeyNeeded bool
	// Database is the database the connection names: the setup's target
	// for a connect-only code, which the page shows before approval.
	Database Target
	// Connected is the database and role the connection reached, as the
	// server says them, for the confirm step (ConnectedAs).
	Connected Connected
	// Tables are, for an agent.allTables code, the tables the agent will
	// get, in name order; ReadOnly are those among them it may only read
	// (no primary key, so the guard cannot key its writes); Excluded are the
	// tables of its schemas left out because the admin role does not own
	// them. All empty otherwise.
	Tables   []string
	ReadOnly []string
	Excluded []ExcludedTable
	// RunsAsInstall is an AGENT code with a verifier whose role does
	// not exist: Run creates the role as an INSTALL code does.
	RunsAsInstall bool
	// Ticked is whether the page shows Tables with ticks and Run needs
	// Request.Included: an INSTALL code with agent.allTables, and an AGENT
	// code that runs as an INSTALL with agent.allTables or no tables.
	Ticked bool
	// Columns are every ordinary column of the tables the agent will get
	// (Tables, else the code's write and read tables), by table in name
	// order and then column order, with its class in the database now
	// (UNCLASSIFIED with none stored, and in a database with no guard
	// yet); for an UPGRADE code, which names no agent, the columns of every
	// table with a readable column (pii_readable_columns()). Only with
	// Request.ConnectPage.
	Columns []ColumnLabel
	// Passkeys are the database's active passkeys, for a code with a
	// target (the connect page's passkey list, CONTRACT.md, Update on the
	// connect page). Only with Request.ConnectPage.
	Passkeys []ActivePasskey
}

// ColumnLabel is a column and its class now (CONTRACT.md, Connect, Column
// labels on the connect page).
type ColumnLabel struct {
	// Table is schema.table.
	Table, Column string
	Label
}

// Label is a class: PUBLIC, IDENTIFIER, FREE_TEXT, SECRET or UNCLASSIFIED,
// EntityType with IDENTIFIER (EMAIL, PHONE, PERSON_NAME, ADDRESS or OTHER),
// PhoneRegion with PHONE (ISO 3166-1 alpha-2, upper case).
type Label struct {
	Class, EntityType, PhoneRegion string
}

// ColumnClass is a class the person set on a column on the connect page,
// with Was, the class the column had when Check returned it.
type ColumnClass struct {
	// Table is schema.table, one of the tables the agent gets.
	Table, Column string
	// Label is PUBLIC, IDENTIFIER (with its entity type, and a region with
	// PHONE) or SECRET.
	Label
	Was Label
}

// ExcludedTable is a table an agent.allTables setup leaves out.
type ExcludedTable struct {
	// Table is schema.table.
	Table string
	// Owner is the role that owns it.
	Owner string
}

// ConnDatabase is the database a connection names, as a setup's target:
// the Supabase project ref when the host or user names one.
func ConnDatabase(cfg *pgx.ConnConfig) Target {
	t := setupcode.ConnTarget(cfg.Host, int(cfg.Port), cfg.Database, cfg.User)
	return Target{Host: t.Host, Port: t.Port, Database: t.Database, SupabaseRef: t.SupabaseRef}
}

// NothingToDo is an UPGRADE code whose guard the database already has.
type NothingToDo struct {
	// Installed is the database's guard version; To is the code's.
	Installed int
	To        int
}

// Questions are what the person answers before the setup runs.
type Questions struct {
	// RowSecurity are the agent's tables where row-level security hides
	// every row from its role: yes lets the agent see all of them (a
	// policy), no leaves them hidden. Answered in Answers.AllRows.
	RowSecurity []RowSecurityQuestion
	// OutsidePublic are the agent's tables outside schema public. The
	// summary flags each; nothing is asked and Run takes no answer for
	// them.
	OutsidePublic []string
}

// RowSecurityQuestion is one table row-level security hides from the
// agent.
type RowSecurityQuestion struct {
	Table string
	// Rows is how many rows the table holds.
	Rows int64
	// Write is whether the agent may change the table's rows.
	Write bool
	// Text is the question as basalt init asks it.
	Text string
}

// rollbackTimeout bounds the rollback of a failed setup, which runs even
// when the caller's context is done.
const rollbackTimeout = 5 * time.Second

// adminTx runs the setup's transaction on the admin connection conn. A
// commit that fails without the database's answer is a
// setuprun.UnconfirmedError; one the database answered (an error of its
// own, or a commit that became a rollback), one never sent, and fn's
// error are known failures. The transaction rolls back on any of them, and
// on a panic in fn.
func adminTx(conn *pgx.Conn) setuprun.TxRunner {
	return func(ctx context.Context, fn func(setuprun.Querier) error) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer rollback(ctx, tx) // after a commit, a no-op
		if err := fn(pgquerier.Neutralize(tx)); err != nil {
			return err
		}
		return commitOutcome(tx.Commit(ctx))
	}
}

// rollback rolls tx back, within rollbackTimeout of now whatever ctx says.
func rollback(ctx context.Context, tx pgx.Tx) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	_ = tx.Rollback(rctx)
}

// commitOutcome is err from a commit, as a setuprun.UnconfirmedError when
// the database may have applied it without answering: not one it
// answered, not one that became a rollback, and not one the driver never
// sent (pgconn.SafeToRetry).
func commitOutcome(err error) error {
	var pg *pgconn.PgError
	switch {
	case err == nil, errors.As(err, &pg), errors.Is(err, pgx.ErrTxCommitRollback), pgconn.SafeToRetry(err):
		return err
	}
	return &setuprun.UnconfirmedError{Err: err}
}

// sameTx runs the setup's statements in tx, the transaction Run already
// opened: no transaction of their own.
func sameTx(tx setuprun.Querier) setuprun.TxRunner {
	return func(_ context.Context, fn func(setuprun.Querier) error) error { return fn(tx) }
}

// pgxTx is the transaction adminTx handed the setup, for the writes in it
// that run on the driver itself (labels, the trust pin, the passkey).
func pgxTx(q setuprun.Querier) pgx.Tx {
	tx, ok := pgquerier.Unwrap(q).(pgx.Tx)
	if !ok {
		panic("setup: the setup's transaction did not come from adminTx")
	}
	return tx
}

// adminAt is where the admin connection conn points, for the setup's
// target check.
func adminAt(conn *pgx.Conn) setuprun.ConnConfig {
	cfg := conn.Config()
	at := setuprun.ConnConfig{Host: cfg.Host, Port: cfg.Port, Database: cfg.Database, User: cfg.User}
	for _, fb := range cfg.Fallbacks {
		at.Fallbacks = append(at.Fallbacks, setuprun.ConnHost{Host: fb.Host, Port: fb.Port})
	}
	return at
}

// Check applies Describe's checks, then the database's, in the contract's
// order: the connection's database against the code's target
// (TARGET_MISMATCH), PREFIX_MISMATCH, USED, SUPERSEDED, ROLE_EXISTS,
// ROLE_MISSING and ENGINE_REVOKED, then a missing table (TABLES_MISSING).
// It changes nothing. A refusal is an *Error.
func Check(ctx context.Context, conn *pgx.Conn, req Request) (Checked, error) {
	s, err := newSetup(req)
	if err != nil {
		return Checked{}, asError(err)
	}
	p, err := s.Prepare(ctx, pgquerier.Neutralize(conn), adminAt(conn))
	if err != nil {
		return Checked{}, asError(err)
	}
	out := Checked{Description: describe(s), Database: ConnDatabase(conn.Config()), RunsAsInstall: s.RunsAsInstall(), Ticked: s.Ticked()}
	if out.Connected, err = ConnectedAs(ctx, conn); err != nil {
		return Checked{}, asError(err)
	}
	if p.NothingToDo {
		out.NothingToDo = nothingToDo(p)
		return out, nil
	}
	out.Summary, out.EngineLines = p.Summary(), p.EngineLines()
	out.Questions = questions(p)
	tables := s.Tables()
	out.Tables = append(slices.Clone(tables.Write), tables.ReadOnly...)
	slices.Sort(out.Tables)
	out.ReadOnly = slices.Clone(tables.ReadOnly)
	for _, e := range tables.Excluded {
		out.Excluded = append(out.Excluded, ExcludedTable(e))
	}
	if out.PasskeyNeeded, err = setuprun.PasskeyNeeded(ctx, store, pgquerier.Neutralize(conn), false); err != nil {
		return Checked{}, asError(err)
	}
	if !req.ConnectPage { // the laptop command shows no labels and no passkeys
		return out, nil
	}
	labels, err := checkLabels(ctx, conn, s)
	if err != nil {
		return Checked{}, asError(err)
	}
	for _, l := range labels {
		out.Columns = append(out.Columns, ColumnLabel{Table: l.Table, Column: l.Column, Label: Label(l.Label)})
	}
	if s.P.Target != nil {
		if out.Passkeys, err = activePasskeys(ctx, conn); err != nil {
			return Checked{}, asError(err)
		}
	}
	return out, nil
}

// checkLabels are the columns Check shows: the agent's tables', or, for an
// UPGRADE code, every readable column's table.
func checkLabels(ctx context.Context, conn *pgx.Conn, s *setuprun.Setup) ([]guardmodel.ColumnLabel, error) {
	if s.P.Agent == nil {
		return guard.ReadReadableLabels(ctx, conn, s.Names)
	}
	return guard.ReadLabels(ctx, conn, s.Names, agentTables(s))
}

// agentTables are the tables the agent gets, in name order: for an AGENT
// code that keeps the role's grants, the ones it holds.
func agentTables(s *setuprun.Setup) []string { return s.AgentTables() }

// newSetup is setuprun.NewSetuprun for req, with its ticked tables.
func newSetup(req Request) (*setuprun.Setup, error) {
	s, err := setuprun.NewSetuprun(store, req.Code, req.Now, req.ConnectPage)
	if err != nil {
		return nil, err
	}
	if req.Included != nil {
		s.Include(req.Included.Tables)
	}
	return s, nil
}

func nothingToDo(p *setuprun.Prepared) *NothingToDo {
	return &NothingToDo{Installed: p.State.GuardVersion, To: p.P.Guard.To}
}

func questions(p *setuprun.Prepared) Questions {
	var q Questions
	for _, b := range p.Blind {
		q.RowSecurity = append(q.RowSecurity, RowSecurityQuestion{
			Table: b.Table, Rows: b.Rows, Write: b.Write, Text: setuprun.RLSQuestion(b, p.P.Agent.Name),
		})
	}
	if a := p.P.Agent; a != nil {
		for _, t := range append(slices.Clone(a.Write), a.Read...) {
			if schema, _, _ := strings.Cut(t, "."); schema != "public" {
				q.OutsidePublic = append(q.OutsidePublic, t)
			}
		}
	}
	return q
}

// Answers are the person's answers to Check's questions.
type Answers struct {
	// AllRows are the RowSecurity tables the agent may see every row of.
	AllRows []string
}

// Plan is the SQL Run is about to run.
type Plan struct {
	// SQL is the script for the person to read, the agent's password
	// shown as its verifier.
	SQL string
	// Warnings are for the person before it runs; none stops it.
	Warnings []string
}

// RunInput is what Run needs besides the request.
type RunInput struct {
	Answers Answers
	// Passkey is the person's verified passkey (PasskeyRequest.Verify),
	// registered in the setup's transaction, after the migrations and
	// before record_setup, whether or not the database needs one. A
	// failure to register it rolls the whole setup back. An UPGRADE code
	// with nothing to do runs nothing, so it stores no passkey either
	// (Result.NothingToDo set, Result.Passkey nil).
	Passkey *Passkey
	// AskPasskey is the passkey step (The setup checks,
	// step 7): Run calls it at most once, after the setup committed, and
	// only when the database has no active portal passkey or AddPasskey is
	// set. When it fails, the setup has run and Run returns
	// PASSKEY_NOT_REGISTERED. Set Passkey or AskPasskey, not both.
	//
	// With neither set and a passkey needed, Run refuses PASSKEY_REQUIRED
	// in the transaction, before the setup's script runs: nothing changes.
	AskPasskey func(ctx context.Context) (Passkey, error)
	// AddPasskey asks for the person's passkey even when the database has
	// an active portal passkey.
	AddPasskey bool
	// Approve, when set, is shown the SQL before it runs. An error stops
	// the run with nothing changed, and Run returns that error as it is.
	// It runs inside the setup's open transaction, which holds locks on the
	// agent's row-level security tables and its snapshot, so a caller must
	// not wait on a person there.
	Approve func(Plan) error
	// Committed, when set, is called once the setup's transaction
	// committed, before AskPasskey.
	Committed func(Result)
	// ColumnClasses are the classes the person set on the connect page, at
	// most 500, written in the setup's transaction after the grants, as
	// basalt classify writes them (CONTRACT.md, Connect, Column labels on
	// the connect page). A column whose class stored now is not its Was,
	// or that is gone, refuses the setup CLASSES_CHANGED, nothing changed.
	ColumnClasses []ColumnClass
	// RestPublic writes PUBLIC to every other column of the agent's
	// tables that has no class in the transaction.
	RestPublic bool
	// TrustPin, when set, is the certificate the caller's admin login was
	// verified against with a trustRoot the person trusted on the connect
	// page: Run records it with basalt_meta.record_trust_pin in the setup's
	// transaction (in a transaction of its own for an UPGRADE code with
	// nothing to do). Only a certificate the login was really verified
	// against: the package does not check it.
	TrustPin *TrustPin
}

// TrustPin is a certificate an admin login was verified against: the host
// and port the login reached and the SHA-256 (DER, 64 lowercase hex digits)
// of its chain's top.
type TrustPin struct {
	Host   string
	Port   int
	SHA256 string
}

// maxColumnClasses bounds RunInput.ColumnClasses.
const maxColumnClasses = 500

// checkColumnNames refuses, before any read, a column label whose column
// name is not a plain one (setuprun.PlainColumn: empty, longer than 63
// bytes, or with a control character), as the local setup page does.
func checkColumnNames(in RunInput) error {
	for _, c := range in.ColumnClasses {
		if !setuprun.PlainColumn(c.Column) {
			return asError(&setuprun.SetuprunRefusalError{Code: CodeAnswersInvalid, Message: "the column labels: a class, entity type or phone region the page does not set; nothing changed"})
		}
	}
	return nil
}

// checkColumnClasses applies the rules of ColumnClasses and RestPublic
// that need no database (ANSWERS_INVALID): at most 500, each on a table the
// agent gets, at most once per column, with a class the page may set and a
// Was a column can have. An UPGRADE code names no agent: its columns are
// the readable ones, checked in the setup's transaction (a column outside
// them is CLASSES_CHANGED there).
func checkColumnClasses(s *setuprun.Setup, in RunInput) error {
	if len(in.ColumnClasses) == 0 && !in.RestPublic {
		return nil
	}
	invalid := func(why string) error {
		return asError(&setuprun.SetuprunRefusalError{Code: CodeAnswersInvalid, Message: "the column labels: " + why + "; nothing changed"})
	}
	if len(in.ColumnClasses) > maxColumnClasses {
		return invalid(fmt.Sprintf("more than %d columns", maxColumnClasses))
	}
	var tables []string
	if s.P.Agent != nil {
		tables = agentTables(s)
	}
	seen := map[[2]string]bool{}
	for _, c := range in.ColumnClasses {
		key := [2]string{c.Table, c.Column}
		switch {
		case s.P.Agent != nil && !slices.Contains(tables, c.Table):
			return invalid("a column of a table the agent does not get")
		case seen[key]:
			return invalid("a column given twice")
		case c.Column == "" || !guardmodel.ValidLabel(guardmodel.Label(c.Label)) || !guardmodel.ValidWas(guardmodel.Label(c.Was)):
			return invalid("a class, entity type or phone region the page does not set")
		}
		seen[key] = true
	}
	return nil
}

// Result is what a run did.
type Result struct {
	SetupID string
	// NothingToDo is set when the database's guard already had what an
	// UPGRADE code adds: nothing ran.
	NothingToDo *NothingToDo
	// Ran is whether the setup's transaction committed.
	Ran bool
	// EngineRecorded is whether the code's engine key was recorded.
	EngineRecorded bool
	// Warnings are for the person after the run: tables whose rows the
	// agent cannot see, or that the check failed, with its Postgres error.
	Warnings []string
	// Passkey is the passkey this run registered, nil when none.
	Passkey *RegisteredPasskey
}

// Run checks, plans and runs the setup in one transaction: the migrations,
// the agent role and its grants, the policies on Answers.AllRows, the
// engine, the person's passkey
// (RunInput.Passkey), and record_setup last. Any failure in it leaves the
// database as it was. It first applies every refusal of Describe, then
// refuses a Passkey that PasskeyRequest.Verify did not make
// (PASSKEY_INVALID), then refuses a column label whose column name is not a
// plain one (ANSWERS_INVALID) before any read, then applies every refusal
// of Check, in their order, and refuses an answer to a question Check
// would not ask, or to one question twice (ANSWERS_INVALID). A refusal is
// an *Error. Only with RunInput.AskPasskey
// can the setup run without the passkey it needs: Run then returns
// PASSKEY_NOT_REGISTERED, and Result says the setup ran.
func Run(ctx context.Context, conn *pgx.Conn, req Request, in RunInput) (Result, error) {
	if in.Passkey != nil && in.AskPasskey != nil {
		return Result{}, errors.New("setup: RunInput.Passkey and RunInput.AskPasskey are both set")
	}
	if req.ConnectPage && req.Included == nil {
		req.Included = &Included{} // the page always sends its ticks: none is NO_TABLES
	}
	s, err := newSetup(req)
	if err != nil {
		return Result{}, asError(err)
	}
	if in.Passkey != nil && !in.Passkey.verified() {
		return Result{}, asError(&setuprun.SetuprunRefusalError{Code: CodePasskeyInvalid, Message: "the passkey was not verified; nothing changed"})
	}
	if err := checkColumnNames(in); err != nil {
		return Result{}, err
	}
	var (
		res        Result
		registered *RegisteredPasskey
		// refused is a refusal before the setup's script runs (Prepare, the
		// labels' rules, Plan, Approve): returned as it is, not through
		// Refused.
		refused error
	)
	err = adminTx(conn)(ctx, func(tx setuprun.Querier) error {
		// The setup is checked and planned in its own transaction: nothing
		// changes between the reads the plan rests on and its statements.
		p, err := s.Prepare(ctx, tx, adminAt(conn))
		if err != nil {
			refused = asError(err)
			return refused
		}
		if err := checkColumnClasses(s, in); err != nil {
			refused = err
			return refused
		}
		if p.NothingToDo {
			if err := setuprun.RefuseAnswers(in.Answers.AllRows); err != nil {
				refused = asError(err)
				return refused
			}
			if len(in.ColumnClasses) > 0 || in.RestPublic {
				// Nothing runs, so nothing would carry them: refused, not dropped.
				refused = asError(&setuprun.SetuprunRefusalError{Code: CodeAnswersInvalid, Message: "this setup has nothing to do, so it writes no label; nothing changed"})
				return refused
			}
			res = Result{SetupID: s.P.SetupID, NothingToDo: nothingToDo(p)}
			// The certificate the login was verified against is still
			// recorded (the changed-certificate code of an agent saved with
			// every table in public).
			return recordTrustPin(ctx, pgxTx(tx), in.TrustPin)
		}
		script, err := p.Plan(ctx, in.Answers.AllRows)
		if err != nil {
			refused = asError(err)
			return refused
		}
		if in.Approve != nil {
			if err := in.Approve(Plan{SQL: script.SQL(), Warnings: slices.Clone(script.Warnings)}); err != nil {
				refused = err
				return refused
			}
		}
		res = Result{SetupID: s.P.SetupID, Ran: true, EngineRecorded: p.Engine.Key != nil}
		// The tables the grants cover, read again before the grants name
		// them. A table dropped between this read and the grants still
		// fails the grant itself: SETUP_FAILED, nothing changed.
		first := func(ctx context.Context, q setuprun.Querier) error {
			if err := s.RecheckTables(ctx, q); err != nil {
				return err
			}
			if in.Passkey == nil && in.AskPasskey == nil {
				// Refused before the script runs, not after it: nothing was
				// changed to roll back.
				return requirePasskey(ctx, q, in.AddPasskey)
			}
			return nil
		}
		inTx := func(ctx context.Context, q setuprun.Querier) error {
			tx := pgxTx(q)
			if err := writeLabels(ctx, tx, s, in, req.Now); err != nil {
				return err
			}
			// The certificate the caller logged in against, recorded in the
			// ledger (CONTRACT.md, Pinning on first use, Audit).
			if err := recordTrustPin(ctx, tx, in.TrustPin); err != nil {
				return err
			}
			if in.Passkey != nil {
				var err error
				registered, err = registerInTx(ctx, tx, in.Passkey)
				return err
			}
			return nil // none needed (checked first), or the laptop asks after the commit
		}
		return setuprun.ApplySetupWith(ctx, store, sameTx(tx), script, first, inTx)
	})
	if refused != nil {
		return Result{}, refused
	}
	if err != nil {
		return Result{}, asError(setuprun.Refused(ctx, store, pgquerier.Neutralize(conn), s.P, err))
	}
	if res.NothingToDo != nil {
		return res, nil
	}
	res.Passkey = registered
	if s.P.Agent != nil {
		res.Warnings = setuprun.RLSBlindWarnings(ctx, store, pgquerier.Neutralize(conn), s.P.Role(), s.Spec())
	}
	if in.Committed != nil {
		in.Committed(res)
	}
	if in.AskPasskey == nil {
		return res, nil
	}
	asked, err := askPasskey(ctx, conn, in)
	if err != nil {
		return res, asError(setuprun.PasskeyFailed(s.P, err))
	}
	res.Passkey = asked
	return res, nil
}

// recordTrustPin records t, when set, in the setup's transaction tx.
func recordTrustPin(ctx context.Context, tx pgx.Tx, t *TrustPin) error {
	if t == nil {
		return nil
	}
	return guard.RecordTrustPin(ctx, tx, t.Host, t.Port, t.SHA256)
}

// writeLabels writes in.ColumnClasses and in.RestPublic in the setup's
// transaction. Its tables are the agent role's (setuprun.Setup.AgentTables): for an
// AGENT code that keeps the role's grants, the grants it holds, since such
// a code names no tables; otherwise the code's tables. An UPGRADE code
// names no agent, so its tables are the readable ones, read after the
// migrations. The local setup page takes the person's picks instead.
func writeLabels(ctx context.Context, tx pgx.Tx, s *setuprun.Setup, in RunInput, now time.Time) error {
	if len(in.ColumnClasses) == 0 && !in.RestPublic {
		return nil
	}
	changes := make([]guardmodel.LabelChange, 0, len(in.ColumnClasses))
	for _, c := range in.ColumnClasses {
		changes = append(changes, guardmodel.LabelChange{Table: c.Table, Column: c.Column, Label: guardmodel.Label(c.Label), Was: guardmodel.Label(c.Was)})
	}
	var tables []string
	switch {
	case s.P.Agent != nil:
		tables = agentTables(s)
	default:
		// An UPGRADE code: every readable column's table, read after the
		// migrations in this transaction.
		var err error
		if tables, err = guard.ReadableTables(ctx, tx, s.Names); err != nil {
			return err
		}
	}
	_, err := guard.WriteLabels(ctx, tx, s.Names, tables, changes, in.RestPublic, now)
	if errors.Is(err, guardmodel.ErrClassesChanged) {
		return &setuprun.SetuprunRefusalError{
			Code: CodeClassesChanged, Err: err,
			Message: "a column's label changed since the page showed it (someone classified it, or the column is gone), so the setup did not run and nothing changed: read the labels again",
		}
	}
	return err
}

// Error is a refused or failed step. Message is what the person reads:
// this package's sentences, which name a Postgres error by its SQLSTATE
// and never carry the database's or the driver's own words. Those stay in
// the error Unwrap returns, for a log.
type Error struct {
	// Code is one of Codes().
	Code    string
	Message string
	err     error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.err }

// Codes this package returns besides the setup code's refusals
// (CONTRACT.md, The setup code).
const (
	// CodeEngineRevoked is a code whose engine the database revoked.
	CodeEngineRevoked = setuprun.CodeEngineRevoked
	// CodeTargetMismatch is a connection to another database than the
	// code's target.
	CodeTargetMismatch = setuprun.SetuprunCodeTargetMismatch
	// CodeTablesMissing is an agent table the database does not have.
	CodeTablesMissing = setuprun.CodeTablesMissing
	// CodeAnswersInvalid is an answer to a question the setup does not ask.
	CodeAnswersInvalid = setuprun.SetuprunCodeAnswersInvalid
	// CodePasskeyRequired is a setup that needs the person's passkey, run
	// with none: nothing changed.
	CodePasskeyRequired = setuprun.SetuprunCodePasskeyRequired
	// CodePasskeyInvalid is a RunInput.Passkey that PasskeyRequest.Verify
	// did not make.
	CodePasskeyInvalid = setuprun.SetuprunCodePasskeyInvalid
	// CodePasskeyNotRegistered is a setup that ran without registering the
	// passkey it needed: only with RunInput.AskPasskey.
	CodePasskeyNotRegistered = setuprun.CodePasskeyMissing
	// CodeNoTables is an agent.allTables code whose schemas hold no table
	// the admin role owns, or a connect page that ticked none: nothing
	// changed.
	CodeNoTables = setuprun.SetuprunCodeNoTables
	// CodeTablesChanged is a setup whose tables changed since they were
	// listed: nothing changed.
	CodeTablesChanged = setuprun.SetuprunCodeTablesChanged
	// CodeClassesChanged is a column label whose class stored now is not
	// the one the page showed, or whose column is gone: nothing changed.
	CodeClassesChanged = setuprun.SetuprunCodeClassesChanged
	// CodeConnectOnly is a connect-only code given without
	// Request.ConnectPage: only the connect page runs it.
	CodeConnectOnly = string(setupcode.RefusalConnectOnly)
	// CodeGuardUnusable is a database with an older BasaltDB install this
	// version can neither install over nor update: remove it first, as the
	// message's link says. Nothing changed.
	CodeGuardUnusable = setuprun.SetuprunCodeGuardUnusable
	// CodeSetupUnconfirmed is a setup whose commit got no answer from the
	// database: it may or may not have run. Check tells which.
	CodeSetupUnconfirmed = setuprun.SetuprunCodeSetupUnconfirmed
	// CodeSetupFailed is any other failure: the database or its driver.
	// Nothing changed. Its Message names the Postgres error and the step,
	// never the database's own words.
	CodeSetupFailed = "SETUP_FAILED"
)

// codes is every Error.Code this package returns.
var codes = []string{
	string(setupcode.RefusalNotASetupCode), string(setupcode.RefusalUnsupportedFormat), string(setupcode.RefusalDamaged),
	string(setupcode.RefusalInvalid), string(setupcode.RefusalExpired), string(setupcode.RefusalSetupIDInFuture),
	string(setupcode.RefusalExpiryTooFar), string(setupcode.RefusalBinaryTooOld), string(setupcode.RefusalGuardTooOld),
	string(setupcode.RefusalPrefixMismatch), string(setupcode.RefusalUsed), string(setupcode.RefusalSuperseded),
	string(setupcode.RefusalRoleExists), string(setupcode.RefusalRoleMissing),
	CodeEngineRevoked, CodeTargetMismatch, CodeTablesMissing,
	CodeAnswersInvalid, CodePasskeyRequired, CodePasskeyInvalid, CodePasskeyNotRegistered, CodeSetupFailed,
	CodeNoTables, CodeConnectOnly, CodeTablesChanged, CodeClassesChanged, CodeGuardUnusable,
	CodeSetupUnconfirmed,
}

// Codes is every Error.Code this package returns: the setup code's
// refusals and the Code constants. A code outside it is never returned;
// an unknown failure is CodeSetupFailed.
func Codes() []string { return slices.Clone(codes) }

func asError(err error) error {
	if err == nil {
		return nil
	}
	code := CodeSetupFailed
	var r *setuprun.SetuprunRefusalError
	var se *setupcode.Error
	switch {
	case errors.As(err, &r):
		code = r.Code
	case errors.As(err, &se):
		code = string(se.Refusal)
	}
	if !slices.Contains(codes, code) {
		code = CodeSetupFailed
	}
	msg := err.Error()
	if code == CodeSetupFailed && (r == nil || r.Code != CodeSetupFailed) {
		// A failure of the database or the driver: a fixed sentence with
		// the Postgres error and the step; their words stay in the error.
		msg = setuprun.FailedMessage(setuprun.FailedStep("setup", err), setuprun.SQLStateOf(err))
	}
	return &Error{Code: code, Message: msg, err: err}
}
