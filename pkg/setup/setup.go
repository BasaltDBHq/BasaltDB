// Package setup runs a Basalt setup code against a person's database, as
// basalt init --setup-code does on their own computer (CONTRACT.md, Setup
// from your laptop), for a program other than the basalt CLI. The CLI runs
// on it too, so both run the same checks, questions and SQL.
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
// databases, hosts, roles and tables, never a connection string. Some
// carry the database's or the driver's own words (see Error and
// Result.Warnings). A caller behind a transaction pooler opens the
// connection with pgx.QueryExecModeExec, as basalt does.
package setup

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// Request is what every step is given.
type Request struct {
	// Code is the setup code (basalt-setup.1....). Whitespace in it is
	// ignored, so a wrapped copy works.
	Code string
	// Now is the clock the code's times are checked against.
	Now time.Time
	// EngineURL is the address to record with the code's engine key
	// (https://<host>[:<port>]); "" records none.
	EngineURL string
	// ConnectPage accepts a connect-only code (no target), which only the
	// connect service runs, with the database of the connection it opened.
	// Unset, such a code is refused CONNECT_ONLY first, as the laptop
	// command refuses it.
	ConnectPage bool
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
	// AllTablesSchemas.
	Write []string
	Read  []string
	// AllTablesSchemas are, for an agent.allTables code, the schemas whose
	// tables the agent gets (Check lists them); nil otherwise.
	AllTablesSchemas []string
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
	// EngineURL is the request's engine address in its written form.
	EngineURL string
	// Summary is the summary's fixed lines, without the database's state:
	// an UPGRADE code's line names the guard version the code was made
	// against. Check's Summary is the one to show before running.
	Summary []string
}

// Describe decodes the code and applies the checks that need no database,
// in the contract's order: the engine address's rules, the codec
// (NOT_A_SETUP_CODE, UNSUPPORTED_FORMAT, DAMAGED, INVALID), the clock
// (EXPIRED, SETUP_ID_IN_FUTURE, EXPIRY_TOO_FAR), this build's guard
// (BINARY_TOO_OLD, GUARD_TOO_OLD) and ENGINE_KEY_MISSING. A refusal is an
// *Error.
func Describe(req Request) (Description, error) {
	s, err := setuprun.New(req.Code, req.Now, req.EngineURL, req.ConnectPage)
	if err != nil {
		return Description{}, asError(err)
	}
	return describe(s), nil
}

func describe(s *setuprun.Setup) Description {
	p := s.P
	d := Description{
		SetupID: p.SetupID, Kind: Kind(p.Kind), AgentWord: setuprun.AgentWord(p), AgentRole: p.Role(), Prefix: p.Prefix,
		GuardFrom: p.Guard.From, GuardTo: p.Guard.To, ExpiresAt: s.Expires, Fingerprint: p.Fingerprint(), EngineURL: s.EngineURL,
		Summary: setupcode.Summary(p, setupcode.SummaryState{GuardVersion: p.Guard.From}),
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
	}
	if p.Engine != nil {
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
	// Tables are, for an agent.allTables code, the tables the agent will
	// get, in name order; ReadOnly are those among them it may only read
	// (no primary key, so the guard cannot key its writes); Excluded are the
	// tables of its schemas left out because the admin role does not own
	// them. All empty otherwise.
	Tables   []string
	ReadOnly []string
	Excluded []ExcludedTable
	// RunsAsInstall is a connect-only recovery AGENT code whose role does
	// not exist: Run creates the role as an INSTALL code does.
	RunsAsInstall bool
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
	// Revoke are the other engines recorded at the request's engine
	// address: yes revokes one in the setup's transaction. Answered in
	// Answers.Revoke.
	Revoke []RevokeQuestion
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

// RevokeQuestion is one other engine recorded at the engine address.
type RevokeQuestion struct {
	EngineID    string
	Fingerprint string
	URL         string
	RecordedAt  time.Time
	// Text is the question as basalt init asks it.
	Text string
}

// Check applies Describe's checks, then the database's, in the contract's
// order: the connection's database against the code's target
// (TARGET_MISMATCH), PREFIX_MISMATCH, USED, SUPERSEDED, ROLE_EXISTS,
// ROLE_MISSING and ENGINE_REVOKED, then a missing table (TABLES_MISSING).
// It changes nothing. A refusal is an *Error.
func Check(ctx context.Context, conn *pgx.Conn, req Request) (Checked, error) {
	s, err := setuprun.New(req.Code, req.Now, req.EngineURL, req.ConnectPage)
	if err != nil {
		return Checked{}, asError(err)
	}
	p, err := s.Prepare(ctx, conn)
	if err != nil {
		return Checked{}, asError(err)
	}
	out := Checked{Description: describe(s), Database: ConnDatabase(conn.Config()), RunsAsInstall: s.RunsAsInstall()}
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
	if out.PasskeyNeeded, err = setuprun.PasskeyNeeded(ctx, conn, false); err != nil {
		return Checked{}, asError(err)
	}
	return out, nil
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
	for _, e := range p.Engine.SameAddress {
		q.Revoke = append(q.Revoke, RevokeQuestion{
			EngineID: e.ID, Fingerprint: channel.FingerprintOf(e.ID), URL: *e.URL, RecordedAt: e.RecordedAt, Text: setuprun.RevokeQuestion(e),
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
	// Revoke are the engine ids of the Revoke questions answered yes.
	Revoke []string
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
	// AskPasskey is the laptop's passkey step (basalt init --setup-code,
	// step 7): Run calls it at most once, after the setup committed, and
	// only when the database has no active portal passkey or AddPasskey is
	// set. When it fails, the setup has run and Run returns
	// PASSKEY_NOT_REGISTERED. Set Passkey or AskPasskey, not both.
	//
	// With neither set and a passkey needed, Run refuses PASSKEY_REQUIRED
	// in the transaction, which rolls back: nothing changes.
	AskPasskey func(ctx context.Context) (Passkey, error)
	// AddPasskey asks for the person's passkey even when the database has
	// an active portal passkey.
	AddPasskey bool
	// Approve, when set, is shown the SQL before it runs. An error stops
	// the run with nothing changed, and Run returns that error as it is.
	Approve func(Plan) error
	// Committed, when set, is called once the setup's transaction
	// committed, before AskPasskey.
	Committed func(Result)
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
	// agent cannot see, or that the check failed, with the database's own
	// words.
	Warnings []string
	// Passkey is the passkey this run registered, nil when none.
	Passkey *RegisteredPasskey
}

// Run checks, plans and runs the setup in one transaction: the migrations,
// the agent role and its grants, the policies on Answers.AllRows, the
// engine and the engines in Answers.Revoke, the person's passkey
// (RunInput.Passkey), and record_setup last. Any failure in it leaves the
// database as it was. It first applies every refusal of Describe, then
// refuses a Passkey that PasskeyRequest.Verify did not make
// (PASSKEY_INVALID), then applies every refusal of Check, in their order,
// and refuses an answer to a question Check would not ask
// (ANSWERS_INVALID). A refusal is an *Error. Only with RunInput.AskPasskey
// can the setup run without the passkey it needs: Run then returns
// PASSKEY_NOT_REGISTERED, and Result says the setup ran.
func Run(ctx context.Context, conn *pgx.Conn, req Request, in RunInput) (Result, error) {
	if in.Passkey != nil && in.AskPasskey != nil {
		return Result{}, errors.New("setup: RunInput.Passkey and RunInput.AskPasskey are both set")
	}
	s, err := setuprun.New(req.Code, req.Now, req.EngineURL, req.ConnectPage)
	if err != nil {
		return Result{}, asError(err)
	}
	if in.Passkey != nil && !in.Passkey.verified() {
		return Result{}, asError(&setuprun.RefusalError{Code: CodePasskeyInvalid, Message: "the passkey was not verified; nothing changed"})
	}
	p, err := s.Prepare(ctx, conn)
	if err != nil {
		return Result{}, asError(err)
	}
	if p.NothingToDo {
		if err := setuprun.RefuseAnswers(in.Answers.AllRows, in.Answers.Revoke); err != nil {
			return Result{}, asError(err)
		}
		return Result{SetupID: s.P.SetupID, NothingToDo: nothingToDo(p)}, nil
	}
	script, err := p.Plan(ctx, in.Answers.AllRows, in.Answers.Revoke)
	if err != nil {
		return Result{}, asError(err)
	}
	if in.Approve != nil {
		if err := in.Approve(Plan{SQL: script.SQL(), Warnings: slices.Clone(script.Warnings)}); err != nil {
			return Result{}, err
		}
	}
	var registered *RegisteredPasskey
	inTx := func(ctx context.Context, tx pgx.Tx) error {
		// The tables the grants cover, read again in this transaction.
		if err := s.RecheckTables(ctx, tx); err != nil {
			return err
		}
		switch {
		case in.Passkey != nil:
			var err error
			registered, err = registerInTx(ctx, tx, in.Passkey)
			return err
		case in.AskPasskey == nil:
			return requirePasskey(ctx, tx, in.AddPasskey)
		}
		return nil // the laptop asks after the commit
	}
	if err := setuprun.ApplySetupWith(ctx, conn, script, inTx); err != nil {
		return Result{}, asError(setuprun.Refused(ctx, conn, s.P, err))
	}
	res := Result{SetupID: s.P.SetupID, Ran: true, EngineRecorded: p.Engine.Key != nil, Passkey: registered}
	if s.P.Agent != nil {
		res.Warnings = setuprun.RLSBlindWarnings(ctx, conn, s.P.Role(), s.Spec())
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

// Error is a refused or failed step. Message is what the person reads.
// With CodeSetupFailed, and with CodePasskeyNotRegistered (after "the setup
// ran but no passkey was registered: "), it may carry the database's or
// the driver's own words; the other codes' messages are this package's
// sentences.
type Error struct {
	// Code is one of Codes().
	Code    string
	Message string
	err     error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.err }

// Codes this package returns besides the setup code's refusals
// (CONTRACT.md, The setup code and basalt init --setup-code).
const (
	// CodeEngineURLInvalid is an engine address the address rules refuse.
	CodeEngineURLInvalid = setuprun.CodeEngineURLInvalid
	// CodeEngineKeyMissing is an engine address for a code without an
	// engine key.
	CodeEngineKeyMissing = setuprun.CodeEngineKeyMissing
	// CodeEngineRevoked is a code whose engine the database revoked.
	CodeEngineRevoked = setuprun.CodeEngineRevoked
	// CodeTargetMismatch is a connection to another database than the
	// code's target.
	CodeTargetMismatch = setuprun.CodeTargetMismatch
	// CodeTablesMissing is an agent table the database does not have.
	CodeTablesMissing = setuprun.CodeTablesMissing
	// CodeAnswersInvalid is an answer to a question the setup does not ask.
	CodeAnswersInvalid = setuprun.CodeAnswersInvalid
	// CodePasskeyRequired is a setup that needs the person's passkey, run
	// with none: nothing changed.
	CodePasskeyRequired = setuprun.CodePasskeyRequired
	// CodePasskeyInvalid is a RunInput.Passkey that PasskeyRequest.Verify
	// did not make.
	CodePasskeyInvalid = setuprun.CodePasskeyInvalid
	// CodePasskeyNotRegistered is a setup that ran without registering the
	// passkey it needed: only with RunInput.AskPasskey.
	CodePasskeyNotRegistered = setuprun.CodePasskeyMissing
	// CodeNoTables is an agent.allTables code whose schemas hold no table
	// the admin role owns: nothing changed.
	CodeNoTables = setuprun.CodeNoTables
	// CodeConnectOnly is a connect-only code given without
	// Request.ConnectPage: only the connect page runs it.
	CodeConnectOnly = string(setupcode.RefusalConnectOnly)
	// CodeSetupFailed is any other failure: the database or its driver.
	// Nothing changed. Its Message may carry the database's own words; a
	// service that shows fixed messages maps it to one.
	CodeSetupFailed = "SETUP_FAILED"
)

// codes is every Error.Code this package returns.
var codes = []string{
	string(setupcode.RefusalNotASetupCode), string(setupcode.RefusalUnsupportedFormat), string(setupcode.RefusalDamaged),
	string(setupcode.RefusalInvalid), string(setupcode.RefusalExpired), string(setupcode.RefusalSetupIDInFuture),
	string(setupcode.RefusalExpiryTooFar), string(setupcode.RefusalBinaryTooOld), string(setupcode.RefusalGuardTooOld),
	string(setupcode.RefusalPrefixMismatch), string(setupcode.RefusalUsed), string(setupcode.RefusalSuperseded),
	string(setupcode.RefusalRoleExists), string(setupcode.RefusalRoleMissing),
	CodeEngineURLInvalid, CodeEngineKeyMissing, CodeEngineRevoked, CodeTargetMismatch, CodeTablesMissing,
	CodeAnswersInvalid, CodePasskeyRequired, CodePasskeyInvalid, CodePasskeyNotRegistered, CodeSetupFailed,
	CodeNoTables, CodeConnectOnly,
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
	var r *setuprun.RefusalError
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
	return &Error{Code: code, Message: err.Error(), err: err}
}
