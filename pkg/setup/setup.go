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
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
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
	// Included are the tables the person left ticked on the connect page
	// (CONTRACT.md, Connect, Tables on the connect page); nil is no ticks
	// (CheckSetup, which lists every table). The connect page ticks tables
	// of an INSTALL code with agent.allTables: Check and Run then cover
	// exactly the included tables (their questions, columns and grants), an
	// entry the listing lacks is TABLES_CHANGED, and none at all is
	// NO_TABLES. For any other code its Tables must be empty
	// (ANSWERS_INVALID). Run refuses such a code without Included,
	// NO_TABLES.
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

// contract is the setup service's contract use case on store.
var contract = setuprun.NewContract(store)

// Describe decodes the code and applies the checks that need no database,
// in the contract's order: the codec
// (NOT_A_SETUP_CODE, UNSUPPORTED_FORMAT, DAMAGED, INVALID), the clock
// (EXPIRED, SETUP_ID_IN_FUTURE, EXPIRY_TOO_FAR), this build's guard
// (BINARY_TOO_OLD, GUARD_TOO_OLD). A refusal is an *Error.
func Describe(req Request) (Description, error) {
	return described(contract.Describe(contractRequest(req)))
}

// described is the service's description of a code, or its refusal.
func described(d setuprun.ContractDescription, err error) (Description, error) {
	return description(d), asError(err)
}

// contractRequest is req as the setup service takes it.
func contractRequest(req Request) setuprun.ContractRequest {
	return setuprun.ContractRequest{Code: req.Code, Now: req.Now, Included: (*setuprun.ContractIncluded)(req.Included)}
}

// description is the service's description of a code.
func description(d setuprun.ContractDescription) Description {
	return Description{
		SetupID: d.SetupID, Kind: Kind(d.Kind), Agent: d.Agent, AgentWord: d.AgentWord, AgentRole: d.AgentRole, Prefix: d.Prefix,
		Target: (*Target)(d.Target), GuardFrom: d.GuardFrom, GuardTo: d.GuardTo, Write: d.Write, Read: d.Read, AllTablesSchemas: d.AllTablesSchemas,
		KeepsGrants: d.KeepsGrants, StatementTimeoutMs: d.StatementTimeoutMs, ExpiresAt: d.ExpiresAt, Fingerprint: d.Fingerprint,
		EngineFingerprint: d.EngineFingerprint, EngineKey: d.EngineKey, TrustPin: d.TrustPin, Summary: d.Summary,
	}
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
	// table with a readable column (pii_readable_columns()).
	Columns []ColumnLabel
	// Passkeys are the database's active passkeys, for a code with a
	// target (the connect page's passkey list, CONTRACT.md, Update on the
	// connect page).
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
	c, err := contract.Check(ctx, setupstore.Port(conn), adminAt(conn), contractRequest(req))
	if err != nil {
		return Checked{}, asError(err)
	}
	out := Checked{
		Description: description(c.Description), Database: ConnDatabase(conn.Config()), Connected: Connected(c.Connected),
		RunsAsInstall: c.RunsAsInstall, Ticked: c.Ticked,
	}
	if c.NothingToDo != nil {
		out.NothingToDo = (*NothingToDo)(c.NothingToDo)
		return out, nil
	}
	out.Summary, out.EngineLines, out.PasskeyNeeded = c.Summary, c.EngineLines, c.PasskeyNeeded
	for _, q := range c.Questions.RowSecurity {
		out.Questions.RowSecurity = append(out.Questions.RowSecurity, RowSecurityQuestion(q))
	}
	out.Questions.OutsidePublic = c.Questions.OutsidePublic
	out.Tables, out.ReadOnly = c.Tables, c.ReadOnly
	for _, e := range c.Excluded {
		out.Excluded = append(out.Excluded, ExcludedTable(e))
	}
	for _, l := range c.Columns {
		out.Columns = append(out.Columns, ColumnLabel{Table: l.Table, Column: l.Column, Label: Label(l.Label)})
	}
	out.Passkeys = activePasskeys(c.Passkeys)
	return out, nil
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
	// Approve's error is Run's as it is, never an *Error.
	var approveErr error
	cin := setuprun.ContractRunInput{AllRows: in.Answers.AllRows, AddPasskey: in.AddPasskey, RestPublic: in.RestPublic}
	if in.Passkey != nil {
		cin.Passkey = &in.Passkey.p
	}
	if in.AskPasskey != nil {
		cin.AskPasskey = func(ctx context.Context) (setuprun.ContractPasskey, error) {
			pk, err := in.AskPasskey(ctx)
			return pk.p, err
		}
	}
	if in.Approve != nil {
		cin.Approve = func(p setuprun.ContractPlan) error {
			approveErr = in.Approve(Plan(p))
			return approveErr
		}
	}
	if in.Committed != nil {
		cin.Committed = func(r setuprun.ContractResult) { in.Committed(result(r)) }
	}
	for _, c := range in.ColumnClasses {
		cin.ColumnClasses = append(cin.ColumnClasses, setuprun.ContractColumnClass{Table: c.Table, Column: c.Column, Label: guardmodel.Label(c.Label), Was: guardmodel.Label(c.Was)})
	}
	if in.TrustPin != nil {
		cin.TrustPin = (*setuprun.ContractTrustPin)(in.TrustPin)
	}
	res, err := contract.Run(ctx, setupstore.Port(conn), adminAt(conn), contractRequest(req), cin)
	if approveErr != nil {
		return Result{}, approveErr
	}
	return result(res), asError(err)
}

// result is the service's account of a run.
func result(r setuprun.ContractResult) Result {
	return Result{
		SetupID: r.SetupID, NothingToDo: (*NothingToDo)(r.NothingToDo), Ran: r.Ran, EngineRecorded: r.EngineRecorded,
		Warnings: r.Warnings, Passkey: (*RegisteredPasskey)(r.Passkey),
	}
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
	CodeNoTables, CodeTablesChanged, CodeClassesChanged, CodeGuardUnusable,
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
