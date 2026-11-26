package setup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The setup contract: Describe, Check and Run of a setup code on an admin
// connection a program other than the basalt CLI opened (pkg/setup, which
// translates its types to and from these). It is its own use case, apart
// from the local setup page's jobs (LocalService).

// Contract runs the setup contract on its backend.
type Contract struct{ be ContractBackend }

// NewContract is the setup contract on be.
func NewContract(be ContractBackend) Contract { return Contract{be: be} }

// ContractRequest is what every step is given (pkg/setup's Request).
type ContractRequest struct {
	Code        string
	Now         time.Time
	ConnectPage bool
	Included    *ContractIncluded
}

// ContractIncluded are the tables ticked on the connect page.
type ContractIncluded struct {
	Tables []string
}

// ContractTarget is the database a code's agent connects to.
type ContractTarget struct {
	Host        string
	Port        int
	Database    string
	SupabaseRef string
}

// ContractDescription is what a setup code asks for (pkg/setup's
// Description).
type ContractDescription struct {
	SetupID            string
	Kind               setupcode.Kind
	Agent              string
	AgentWord          string
	AgentRole          string
	Prefix             string
	Target             *ContractTarget
	GuardFrom          int
	GuardTo            int
	Write              []string
	Read               []string
	AllTablesSchemas   []string
	KeepsGrants        bool
	StatementTimeoutMs int64
	ExpiresAt          time.Time
	Fingerprint        string
	EngineFingerprint  string
	EngineKey          string
	TrustPin           string
	Summary            []string
}

// ContractNothingToDo is an UPGRADE code whose guard the database already
// has.
type ContractNothingToDo struct {
	Installed int
	To        int
}

// ContractQuestions are what the person answers before the setup runs.
type ContractQuestions struct {
	RowSecurity   []ContractRowSecurity
	OutsidePublic []string
}

// ContractRowSecurity is one table row-level security hides from the agent.
type ContractRowSecurity struct {
	Table string
	Rows  int64
	Write bool
	Text  string
}

// ContractConnected is the database and the role a connection reached.
type ContractConnected struct {
	Database, User string
}

// ContractChecked is a setup code checked against the database (pkg/setup's
// Checked, without the database the connection names, which its caller
// reads from the connection's settings).
type ContractChecked struct {
	Description   ContractDescription
	NothingToDo   *ContractNothingToDo
	Summary       []string
	EngineLines   []string
	Questions     ContractQuestions
	PasskeyNeeded bool
	Connected     ContractConnected
	Tables        []string
	ReadOnly      []string
	Excluded      []setupcode.ExcludedTable
	RunsAsInstall bool
	Ticked        bool
	Columns       []guardmodel.ColumnLabel
	// Passkeys are the database's active passkeys: nil in a database with
	// no guard yet, and not nil, though it may be empty, in one with.
	Passkeys []guardmodel.RegisteredPasskey
}

// ContractPlan is the SQL Run is about to run.
type ContractPlan struct {
	SQL      string
	Warnings []string
}

// ContractPasskeyRequest is one registration of the person's portal
// passkey: the request their answer is verified against, and the label the
// passkey is stored with.
type ContractPasskeyRequest struct {
	Req   passkey.RegistrationRequest
	Label string
}

// ContractPasskeyRequestFor rebuilds the registration request of a
// challenge the caller issued, for a passkey named label (1 to
// MaxPasskeyLabel bytes of UTF-8). The request copies the challenge's
// bytes.
func ContractPasskeyRequestFor(challenge, userID []byte, userName, displayName, label string) (ContractPasskeyRequest, error) {
	if label == "" || len(label) > MaxPasskeyLabel || !utf8.ValidString(label) {
		return ContractPasskeyRequest{}, fmt.Errorf("the passkey label must be 1 to %d bytes of UTF-8", MaxPasskeyLabel)
	}
	req, err := RegistrationRequestFor(challenge, userID, userName, displayName)
	if err != nil {
		return ContractPasskeyRequest{}, err
	}
	return ContractPasskeyRequest{Req: req, Label: label}, nil
}

// Verify checks the code the portal's registration page shows
// (basalt-passkey.1....) against the request, and returns the passkey Run
// registers.
func (r ContractPasskeyRequest) Verify(code string) (ContractPasskey, error) {
	cred, err := VerifyRegistrationCode(code, r.Req, passkey.Production)
	if err != nil {
		return ContractPasskey{}, err
	}
	return ContractPasskey{Cred: cred, Label: r.Label}, nil
}

// ContractPasskey is a verified portal passkey registration.
type ContractPasskey struct {
	Cred  passkey.Credential
	Label string
}

func (p *ContractPasskey) verified() bool { return p.Cred.PublicKey != nil }

// stored is the passkey as a run reports it stored.
func (p *ContractPasskey) stored() *ContractStoredPasskey {
	return &ContractStoredPasskey{CredentialID: append([]byte(nil), p.Cred.ID...), RPID: p.Cred.Relying.RPID, Origin: p.Cred.Relying.Origin, Label: p.Label}
}

// ContractStoredPasskey is a passkey a run stored.
type ContractStoredPasskey struct {
	CredentialID []byte
	RPID         string
	Origin       string
	Label        string
}

// ContractColumnClass is a class the person set on a column on the connect
// page, with Was, the class the column had when Check returned it.
type ContractColumnClass struct {
	Table, Column string
	Label, Was    guardmodel.Label
}

// ContractTrustPin is a certificate an admin login was verified against.
type ContractTrustPin struct {
	Host   string
	Port   int
	SHA256 string
}

// ContractRunInput is what Run needs besides the request (pkg/setup's
// RunInput). The caller refuses Passkey and AskPasskey both set.
type ContractRunInput struct {
	AllRows       []string
	Passkey       *ContractPasskey
	AskPasskey    func(ctx context.Context) (ContractPasskey, error)
	AddPasskey    bool
	Approve       func(ContractPlan) error
	Committed     func(ContractResult)
	ColumnClasses []ContractColumnClass
	RestPublic    bool
	TrustPin      *ContractTrustPin
}

// ContractResult is what a run did (pkg/setup's Result).
type ContractResult struct {
	SetupID        string
	NothingToDo    *ContractNothingToDo
	Ran            bool
	EngineRecorded bool
	Warnings       []string
	Passkey        *ContractStoredPasskey
}

// Describe decodes the code and applies the checks that need no database.
func (c Contract) Describe(req ContractRequest) (ContractDescription, error) {
	s, err := NewSetuprun(c.be, req.Code, req.Now, req.ConnectPage)
	if err != nil {
		return ContractDescription{}, err
	}
	return describeContract(s), nil
}

func describeContract(s *Setup) ContractDescription {
	p := s.P
	d := ContractDescription{
		SetupID: p.SetupID, Kind: p.Kind, AgentWord: AgentWord(p), AgentRole: p.Role(), Prefix: p.Prefix,
		GuardFrom: p.Guard.From, GuardTo: p.Guard.To, ExpiresAt: s.Expires, Fingerprint: p.Fingerprint(),
		Summary:  setupcode.Summary(p, setupcode.SummaryState{GuardVersion: p.Guard.From}),
		TrustPin: p.TrustPin,
	}
	if t := p.Target; t != nil {
		d.Target = &ContractTarget{Host: t.Host, Port: t.Port, Database: t.Database, SupabaseRef: t.SupabaseRef}
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

// Check applies Describe's checks, then the database's, on the admin
// connection conn, which points at at. It changes nothing.
func (c Contract) Check(ctx context.Context, conn Querier, at ConnConfig, req ContractRequest) (ContractChecked, error) {
	s, err := c.newSetup(req)
	if err != nil {
		return ContractChecked{}, err
	}
	p, err := s.Prepare(ctx, conn, at)
	if err != nil {
		return ContractChecked{}, err
	}
	out := ContractChecked{Description: describeContract(s), RunsAsInstall: s.RunsAsInstall(), Ticked: s.Ticked()}
	if out.Connected.Database, out.Connected.User, err = c.be.ConnectedAs(ctx, conn); err != nil {
		return ContractChecked{}, err
	}
	if p.NothingToDo {
		out.NothingToDo = contractNothingToDo(p)
		return out, nil
	}
	out.Summary, out.EngineLines = p.Summary(), p.EngineLines()
	out.Questions = contractQuestions(p)
	tables := s.Tables()
	out.Tables = append(slices.Clone(tables.Write), tables.ReadOnly...)
	slices.Sort(out.Tables)
	out.ReadOnly = slices.Clone(tables.ReadOnly)
	out.Excluded = append(out.Excluded, tables.Excluded...)
	if out.PasskeyNeeded, err = PasskeyNeeded(ctx, c.be, conn, false); err != nil {
		return ContractChecked{}, err
	}
	if !req.ConnectPage { // the laptop command shows no labels and no passkeys
		return out, nil
	}
	if out.Columns, err = c.checkLabels(ctx, conn, s); err != nil {
		return ContractChecked{}, err
	}
	if s.P.Target != nil {
		if out.Passkeys, err = c.activePasskeys(ctx, conn); err != nil {
			return ContractChecked{}, err
		}
	}
	return out, nil
}

// checkLabels are the columns Check shows: the agent's tables', or, for an
// UPGRADE code, every readable column's table.
func (c Contract) checkLabels(ctx context.Context, conn Querier, s *Setup) ([]guardmodel.ColumnLabel, error) {
	if s.P.Agent == nil {
		return c.be.ReadReadableLabels(ctx, conn, s.Names)
	}
	return c.be.ReadLabels(ctx, conn, s.Names, s.AgentTables())
}

// activePasskeys are the database's active passkeys; none (nil) in a
// database with no guard yet.
func (c Contract) activePasskeys(ctx context.Context, q Querier) ([]guardmodel.RegisteredPasskey, error) {
	installed, err := c.be.PasskeysInstalled(ctx, q)
	if err != nil {
		return nil, err
	}
	if !installed {
		return nil, nil
	}
	keys, err := c.be.ActivePasskeys(ctx, q)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []guardmodel.RegisteredPasskey{} // listed, and none: not a database without the guard
	}
	return keys, nil
}

// newSetup is NewSetuprun for req, with its ticked tables.
func (c Contract) newSetup(req ContractRequest) (*Setup, error) {
	s, err := NewSetuprun(c.be, req.Code, req.Now, req.ConnectPage)
	if err != nil {
		return nil, err
	}
	if req.Included != nil {
		s.Include(req.Included.Tables)
	}
	return s, nil
}

func contractNothingToDo(p *Prepared) *ContractNothingToDo {
	return &ContractNothingToDo{Installed: p.State.GuardVersion, To: p.P.Guard.To}
}

func contractQuestions(p *Prepared) ContractQuestions {
	var q ContractQuestions
	for _, b := range p.Blind {
		q.RowSecurity = append(q.RowSecurity, ContractRowSecurity{
			Table: b.Table, Rows: b.Rows, Write: b.Write, Text: RLSQuestion(b, p.P.Agent.Name),
		})
	}
	if a := p.P.Agent; a != nil {
		for _, t := range append(slices.Clone(a.Write), a.Read...) {
			if schema, _, _ := strings.Cut(t, "."); schema != publicSchema {
				q.OutsidePublic = append(q.OutsidePublic, t)
			}
		}
	}
	return q
}

// contractRollbackTimeout bounds the rollback of a failed setup, which runs
// even when the caller's context is done.
const contractRollbackTimeout = 5 * time.Second

// AdminTx runs the setup's transaction on the admin connection conn. A
// commit that fails without the database's answer is an UnconfirmedError;
// one the database answered (an error of its own, or a commit that became
// a rollback), one never sent, and fn's error are known failures. The
// transaction rolls back on any of them, and on a panic in fn.
func AdminTx(be ContractBackend, conn Querier) TxRunner {
	return func(ctx context.Context, fn func(Querier) error) error {
		tx, err := be.BeginTx(ctx, conn)
		if err != nil {
			return err
		}
		defer rollbackWithin(ctx, be, tx) // after a commit, a no-op
		if err := fn(tx); err != nil {
			return err
		}
		return commitOutcome(be, be.CommitTx(ctx, tx))
	}
}

// rollbackWithin rolls tx back, within contractRollbackTimeout of now
// whatever ctx says.
func rollbackWithin(ctx context.Context, be ContractBackend, tx Querier) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), contractRollbackTimeout)
	defer cancel()
	_ = be.RollbackTx(rctx, tx)
}

// commitOutcome is err from a commit, as an UnconfirmedError when the
// database may have applied it without answering: not one it answered, not
// one that became a rollback, and not one the driver never sent.
func commitOutcome(be ContractBackend, err error) error {
	if err == nil || be.CommitAnswered(err) {
		return err
	}
	return &UnconfirmedError{Err: err}
}

// sameTx runs the setup's statements in tx, the transaction Run already
// opened: no transaction of their own.
func sameTx(tx Querier) TxRunner {
	return func(_ context.Context, fn func(Querier) error) error { return fn(tx) }
}

// maxContractColumnClasses bounds ContractRunInput.ColumnClasses.
const maxContractColumnClasses = 500

// checkColumnNames refuses, before any read, a column label whose column
// name is not a plain one (PlainColumn: empty, longer than 63 bytes, or with
// a control character), as the local setup page does.
func checkColumnNames(in ContractRunInput) error {
	for _, c := range in.ColumnClasses {
		if !PlainColumn(c.Column) {
			return &SetuprunRefusalError{Code: SetuprunCodeAnswersInvalid, Message: "the column labels: a class, entity type or phone region the page does not set; nothing changed"}
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
func checkColumnClasses(s *Setup, in ContractRunInput) error {
	if len(in.ColumnClasses) == 0 && !in.RestPublic {
		return nil
	}
	invalid := func(why string) error {
		return &SetuprunRefusalError{Code: SetuprunCodeAnswersInvalid, Message: "the column labels: " + why + "; nothing changed"}
	}
	if len(in.ColumnClasses) > maxContractColumnClasses {
		return invalid(fmt.Sprintf("more than %d columns", maxContractColumnClasses))
	}
	var tables []string
	if s.P.Agent != nil {
		tables = s.AgentTables()
	}
	seen := map[[2]string]bool{}
	for _, c := range in.ColumnClasses {
		key := [2]string{c.Table, c.Column}
		switch {
		case s.P.Agent != nil && !slices.Contains(tables, c.Table):
			return invalid("a column of a table the agent does not get")
		case seen[key]:
			return invalid("a column given twice")
		case c.Column == "" || !guardmodel.ValidLabel(c.Label) || !guardmodel.ValidWas(c.Was):
			return invalid("a class, entity type or phone region the page does not set")
		}
		seen[key] = true
	}
	return nil
}

// Run checks, plans and runs the setup in one transaction on the admin
// connection conn, which points at at: the migrations, the agent role and
// its grants, the policies on AllRows, the engine, the person's passkey,
// and record_setup last. Any failure in it leaves the database as it was.
// Its refusals come in pkg/setup's Run order. Approve's error is returned
// as it is.
func (c Contract) Run(ctx context.Context, conn Querier, at ConnConfig, req ContractRequest, in ContractRunInput) (ContractResult, error) {
	if req.ConnectPage && req.Included == nil {
		req.Included = &ContractIncluded{} // the page always sends its ticks: none is NO_TABLES
	}
	s, err := c.newSetup(req)
	if err != nil {
		return ContractResult{}, err
	}
	if in.Passkey != nil && !in.Passkey.verified() {
		return ContractResult{}, &SetuprunRefusalError{Code: SetuprunCodePasskeyInvalid, Message: "the passkey was not verified; nothing changed"}
	}
	if err := checkColumnNames(in); err != nil {
		return ContractResult{}, err
	}
	var (
		res        ContractResult
		registered *ContractStoredPasskey
		// refused is a refusal before the setup's script runs (Prepare, the
		// labels' rules, Plan, Approve): returned as it is, not through
		// Refused.
		refused error
	)
	err = AdminTx(c.be, conn)(ctx, func(tx Querier) error {
		// The setup is checked and planned in its own transaction: nothing
		// changes between the reads the plan rests on and its statements.
		p, err := s.Prepare(ctx, tx, at)
		if err != nil {
			refused = err
			return refused
		}
		if err := checkColumnClasses(s, in); err != nil {
			refused = err
			return refused
		}
		if p.NothingToDo {
			if err := RefuseAnswers(in.AllRows); err != nil {
				refused = err
				return refused
			}
			if len(in.ColumnClasses) > 0 || in.RestPublic {
				// Nothing runs, so nothing would carry them: refused, not dropped.
				refused = &SetuprunRefusalError{Code: SetuprunCodeAnswersInvalid, Message: "this setup has nothing to do, so it writes no label; nothing changed"}
				return refused
			}
			res = ContractResult{SetupID: s.P.SetupID, NothingToDo: contractNothingToDo(p)}
			// The certificate the login was verified against is still
			// recorded (the changed-certificate code of an agent saved with
			// every table in public).
			return c.recordTrustPin(ctx, tx, in.TrustPin)
		}
		script, err := p.Plan(ctx, in.AllRows)
		if err != nil {
			refused = err
			return refused
		}
		if in.Approve != nil {
			if err := in.Approve(ContractPlan{SQL: script.SQL(), Warnings: slices.Clone(script.Warnings)}); err != nil {
				refused = err
				return refused
			}
		}
		res = ContractResult{SetupID: s.P.SetupID, Ran: true, EngineRecorded: p.Engine.Key != nil}
		// The tables the grants cover, read again before the grants name
		// them. A table dropped between this read and the grants still
		// fails the grant itself: SETUP_FAILED, nothing changed.
		first := func(ctx context.Context, q Querier) error {
			if err := s.RecheckTables(ctx, q); err != nil {
				return err
			}
			if in.Passkey == nil && in.AskPasskey == nil {
				// Refused before the script runs, not after it: nothing was
				// changed to roll back.
				return c.requirePasskey(ctx, q, in.AddPasskey)
			}
			return nil
		}
		inTx := func(ctx context.Context, q Querier) error {
			if err := c.writeLabels(ctx, q, s, in, req.Now); err != nil {
				return err
			}
			// The certificate the caller logged in against, recorded in the
			// ledger (CONTRACT.md, Pinning on first use, Audit).
			if err := c.recordTrustPin(ctx, q, in.TrustPin); err != nil {
				return err
			}
			if in.Passkey != nil {
				if err := c.be.RegisterPasskey(ctx, q, in.Passkey.Cred, in.Passkey.Label); err != nil {
					return err
				}
				registered = in.Passkey.stored()
				return nil
			}
			return nil // none needed (checked first), or the laptop asks after the commit
		}
		return ApplySetupWith(ctx, c.be, sameTx(tx), script, first, inTx)
	})
	if refused != nil {
		return ContractResult{}, refused
	}
	if err != nil {
		return ContractResult{}, Refused(ctx, c.be, conn, s.P, err)
	}
	if res.NothingToDo != nil {
		return res, nil
	}
	res.Passkey = registered
	if s.P.Agent != nil {
		res.Warnings = RLSBlindWarnings(ctx, c.be, conn, s.P.Role(), s.Spec())
	}
	if in.Committed != nil {
		in.Committed(res)
	}
	if in.AskPasskey == nil {
		return res, nil
	}
	asked, err := c.askPasskey(ctx, conn, in)
	if err != nil {
		return res, PasskeyFailed(s.P, err)
	}
	res.Passkey = asked
	return res, nil
}

// recordTrustPin records t, when set, in the setup's transaction tx.
func (c Contract) recordTrustPin(ctx context.Context, tx Querier, t *ContractTrustPin) error {
	if t == nil {
		return nil
	}
	return c.be.RecordTrustPin(ctx, tx, t.Host, t.Port, t.SHA256)
}

// writeLabels writes in.ColumnClasses and in.RestPublic in the setup's
// transaction. Its tables are the agent role's (Setup.AgentTables): for an
// AGENT code that keeps the role's grants, the grants it holds, since such
// a code names no tables; otherwise the code's tables. An UPGRADE code
// names no agent, so its tables are the readable ones, read after the
// migrations. The local setup page takes the person's picks instead.
func (c Contract) writeLabels(ctx context.Context, tx Querier, s *Setup, in ContractRunInput, now time.Time) error {
	if len(in.ColumnClasses) == 0 && !in.RestPublic {
		return nil
	}
	changes := make([]guardmodel.LabelChange, 0, len(in.ColumnClasses))
	for _, cc := range in.ColumnClasses {
		changes = append(changes, guardmodel.LabelChange{Table: cc.Table, Column: cc.Column, Label: cc.Label, Was: cc.Was})
	}
	var tables []string
	switch {
	case s.P.Agent != nil:
		tables = s.AgentTables()
	default:
		// An UPGRADE code: every readable column's table, read after the
		// migrations in this transaction.
		var err error
		if tables, err = c.be.ReadableTables(ctx, tx, s.Names); err != nil {
			return err
		}
	}
	_, err := c.be.WriteLabels(ctx, tx, s.Names, tables, changes, in.RestPublic, now)
	if errors.Is(err, guardmodel.ErrClassesChanged) {
		return &SetuprunRefusalError{
			Code: SetuprunCodeClassesChanged, Err: err,
			Message: "a column's label changed since the page showed it (someone classified it, or the column is gone), so the setup did not run and nothing changed: read the labels again",
		}
	}
	return err
}

// requirePasskey refuses PASSKEY_REQUIRED, in the setup's transaction
// before its script runs, when the database needs the person's passkey and
// none was given: nothing changed.
func (c Contract) requirePasskey(ctx context.Context, tx Querier, add bool) error {
	need, err := PasskeyNeeded(ctx, c.be, tx, add)
	if err != nil {
		return err
	}
	if need {
		return &SetuprunRefusalError{Code: SetuprunCodePasskeyRequired, Message: "this setup needs the person's portal passkey, and none was given"}
	}
	return nil
}

// askPasskey is the laptop's passkey step, after the setup committed (step
// 7): it asks for the person's passkey and stores it when the database has
// no active portal passkey, or in.AddPasskey asks for another.
func (c Contract) askPasskey(ctx context.Context, conn Querier, in ContractRunInput) (*ContractStoredPasskey, error) {
	need, err := PasskeyNeeded(ctx, c.be, conn, in.AddPasskey)
	if err != nil || !need {
		return nil, err
	}
	pk, err := in.AskPasskey(ctx)
	if err != nil {
		return nil, err
	}
	if !pk.verified() {
		return nil, errors.New("the passkey was not verified")
	}
	if err := c.be.RegisterPasskey(ctx, conn, pk.Cred, pk.Label); err != nil {
		return nil, err
	}
	return pk.stored(), nil
}
