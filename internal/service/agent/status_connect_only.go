package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
)

// A connect-only setup on the engine (CONTRACT.md, Setup from your laptop,
// The engine and a connect-only code). Until the person confirms the
// database the engine collected, the agent is served by ConnectOnly: it
// holds no credential and no connection, status and confirm_database
// answer, and every other tool is refused.

const (
	toolConfirmDatabase = "confirm_database"
	argSetupID          = "setupId"
	argDatabase         = "database"
	argAnswer           = "answer"
	answerYes           = "YES"
	answerNo            = "NO"
	// The states of confirm_database's result.
	confirmedState = "CONFIRMED"
	refusedState   = "REFUSED"
)

// connectOnlyWaiting is status's message while a connect-only setup waits
// for its address: the engine cannot tell a setup not run yet from an
// address the service lost.
const connectOnlyWaiting = "Waiting for the setup on the connect page. If you already approved it there, open the same link again and approve once more: your bot will connect."

// connectOnlyExpiredHold is the same wait after the code has expired but
// the collect window is still open: the expired link is not reprinted.
const connectOnlyExpiredHold = "Waiting for a setup already started on the connect page. The setup link has expired, so it cannot be opened again. If you already approved it there, your bot will connect."

// connectPortal is where a connect-only code is pasted when its link does
// not fit the link budget.
const connectPortal = "portal.basaltvault.app/connect"

// connectOnlySteps: the person opens the connect link (the code pasted at
// the portal when the link does not fit), pastes the database's connection
// string there only, and the page waits for the bot; the agent ends its
// turn and checks status after.
// connectOnlyWaitingMessage is the SETUP_NOT_RUN message while a
// connect-only setup waits for its address: the live-link wording, or the
// hold wording once the code has expired.
func connectOnlyWaitingMessage(code string) string {
	if code == "" {
		return connectOnlyExpiredHold
	}
	return connectOnlyWaiting
}

func connectOnlySteps(b *Steps, code, fingerprint string, budget int) (string, []toolresult.Link) {
	if code == "" {
		b.EndTurn("End your turn: a setup already started on the connect page may still finish.")
		b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
		return connectOnlyExpiredHold, nil
	}
	if !setupCode.MatchString(code) || fingerprint == "" {
		b.Fail(errors.New("a pending setup needs its code and fingerprint"))
		return "", nil
	}
	url := ConnectLink(code, budget)
	lead := "This agent's setup has not run yet, or its database's address did not reach the agent."
	if url == "" {
		b.OpenGivenLink("Open " + connectPortal + " on your own computer or phone, paste the setup code the agent gave you, and paste your database's connection string on that page only.")
	} else {
		b.OpenLink(url, ConnectOnlyStepText)
	}
	b.EndTurn("End your turn: the person acts on the connect page next.")
	b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	if url == "" {
		return lead + " Open " + connectPortal + ", paste the setup code the agent gave you, check that it shows the setup fingerprint " + fingerprint +
			", and paste your database's connection string there only, never in this chat. If you already approved it, approve once more.", nil
	}
	return ConnectOnlyMessage(lead+" If you already approved it, open the same link and approve once more.", url, fingerprint)
}

// confirmDatabaseSteps: the agent asks the person whether db is their
// database, ends its turn, and calls confirm_database with their answer.
// The engine fills in setupId and database, never answer.
func confirmDatabaseSteps(b *Steps, setupID string, db handoff.Address) string {
	b.AskPerson("Ask the person exactly: The setup points me at " + db.Name() + ". Is that your database?")
	b.EndTurn("End your turn: the person answers next.")
	b.CallTool(toolConfirmDatabase, map[string]any{argSetupID: setupID, argDatabase: databaseArg(db)},
		"Call this with answer set to the person's own yes (YES) or no (NO) about that database. Never answer for them.")
	return "The setup points the agent at " + db.Name() + ". The agent asks you in the chat whether that is your database, and uses it only after you say yes. " +
		"If it is not the one you pasted on the connect page, say no."
}

// databaseArg is db as confirm_database takes it.
func databaseArg(db handoff.Address) map[string]any {
	out := map[string]any{"host": db.Host, "port": db.Port, "database": db.Database}
	if db.SupabaseRef != "" {
		out["supabaseRef"] = db.SupabaseRef
	}
	return out
}

// databaseRefusedSteps: a recovery code, made on the engine's machine.
func databaseRefusedSteps(b *Steps, cmds Commands) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "You said the database the setup reached is not yours, so the agent never logged in there and forgot its address and password. " +
		"The agent gives you a new link to set it up again; paste your own database's connection string there."
}

// addressInvalidSteps: the address the page handed over was refused; the
// next basalt init --remote forgets the setup and makes a recovery code.
func addressInvalidSteps(b *Steps, cmds Commands) string {
	b.AskPerson("Tell the person the database address the connect page handed over was refused, so you did not use it.")
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The database address the connect page handed over was refused, so the agent did not use it. The agent gives you a new link: " +
		"paste your database's connection string there again."
}

// setupNotFoundSteps: the database the person confirmed does not record
// the setup; a new code.
func setupNotFoundSteps(b *Steps, cmds Commands, database string) string {
	where := "the database the agent connected to"
	if database != "" {
		where = database
	}
	b.AskPerson("Tell the person " + shown(where, maxTableChars) + " does not record this agent's setup, and that you make a new setup code.")
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The database you confirmed, " + shown(where, maxTableChars) + ", does not record this agent's setup. The agent gives you a new link to run the setup there."
}

// clockSkewSteps: the clock of the bot's machine is off.
func clockSkewSteps(b *Steps) string {
	b.AskPerson("Tell the person the clock of this machine is more than 5 minutes off, so the agent cannot collect its database's address until it is set right.")
	b.EndTurn("End your turn: the person fixes the clock next.")
	return "The clock of the agent's machine is more than 5 minutes off, so the agent cannot collect your database's address. Set the machine's clock right (turn on automatic time), then tell the agent."
}

// engineAsRootSteps: the engine was started as root; it
// must run as the agent's OS user to collect the address.
func engineAsRootSteps(b *Steps) string {
	b.AskPerson("Tell the person the engine runs as root, so it cannot pick up this agent's database address until it is restarted as the engine's user (the owner of its state directory).")
	b.EndTurn("End your turn: the person restarts the engine next.")
	return "The engine on the agent's machine runs as root, so it cannot pick up this agent's database address. " +
		"Restart it as the engine's user (the owner of its state directory), then tell the agent."
}

// unreachableFromBotSteps: the bot's machine cannot reach the collected
// database; the person runs the same link with a string it can reach.
func unreachableFromBotSteps(b *Steps, code string, budget int, db handoff.Address) string {
	url := ConnectLink(code, budget)
	fix := "allow the agent's machine in your database's firewall, or run the same link again with a connection string the agent's machine can reach"
	if db.SupabaseRef != "" {
		fix = "open the same link again and paste your Supabase project's pooler connection string (Connect, Session pooler) instead"
	}
	text := "Open the same link again and approve once more with a connection string the agent's machine can reach, or open the database's firewall to it."
	if url == "" {
		b.OpenGivenLink(text)
	} else {
		b.OpenLink(url, text)
	}
	b.EndTurn("End your turn: the person acts next.")
	b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	// The link is in the step; the message names the fix only.
	return "The setup ran, but the agent's machine cannot reach " + db.Name() + ". To fix it, " + fix + ", then tell the agent."
}

// trustRootMismatchSteps: the collected database presents another
// certificate authority to the bot's machine than the one the person
// trusted on the connect page; nothing was pinned.
func trustRootMismatchSteps(b *Steps, code string, budget int, db handoff.Address) string {
	url := ConnectLink(code, budget)
	text := "Open the same link again: the page reads the database's certificate again. Check it against your provider's console before you trust it."
	if url == "" {
		b.OpenGivenLink(text)
	} else {
		b.OpenLink(url, text)
	}
	b.EndTurn("End your turn: the person acts next.")
	b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	return "The setup ran, but " + db.Name() + " shows the agent's machine another certificate authority than the one you trusted on the connect page, so the agent trusts nothing and does not sign in. " +
		"Open the same link again and check the certificate against your provider's console. If it changes again, something between the agent's machine and your database may be in the way."
}

// --- the result of confirm_database ---

// ConfirmResult is confirm_database's result.
type ConfirmResult struct {
	State         string                `json:"state"`
	Database      handoff.Address       `json:"database"`
	PersonMessage string                `json:"personMessage,omitempty"`
	Links         []toolresult.Link     `json:"links,omitempty"`
	NextSteps     []toolresult.NextStep `json:"nextSteps"`
}

// confirmedSteps: the engine restarts the agent on its credential; status
// says whether the database records the setup.
func confirmedSteps(b *Steps) string {
	b.CallTool(toolStatus, map[string]any{}, "Call status: it shows whether the database records the setup, and the agent works once it does.")
	return ""
}

// refusedResultSteps: the address and the password are gone; a new code.
func refusedResultSteps(b *Steps, cmds Commands) string {
	return databaseRefusedSteps(b, cmds)
}

// --- the served agent ---

// Handoff is the engine's connect-only setup (handoff.Pending).
type Handoff interface {
	State() handoff.State
	StatusCollect(ctx context.Context) handoff.State
	Confirm(ctx context.Context, setupID string, db handoff.Address, yes bool) (handoff.Answer, error)
}

// ConnectOnly serves an agent whose connect-only setup waits for its
// database: status, confirm_database, and every other tool refused.
type ConnectOnly struct {
	Name       string
	Commands   Commands
	OperatedBy string
	SameUser   bool
	// StartedBy is why this engine started (hand, mcp or crash).
	StartedBy string
	PagesBase string
	// PagesOrigin is the origin of the local pages when served.
	PagesOrigin   string
	ConnectBudget int
	Vault         VaultReporter
	Handoff       Handoff
	Log           *slog.Logger
	Now           func() time.Time
	// Errors maps a failure to the contract's tool error; LatestGuardVersion
	// is the basalt_meta version this build installs.
	Errors             ErrorMap
	LatestGuardVersion func() int
}

// guide is a Service with only what the error guidance reads.
func (c ConnectOnly) guide() *Service {
	return &Service{deps: Deps{
		Core:   CoreDeps{Name: c.Name, Commands: c.Commands.OperatedBy(c.OperatedBy), Log: c.Log, Now: c.Now, Errors: c.Errors},
		Status: StatusDeps{ConnectBudget: c.ConnectBudget},
	}}
}

// Tools are every IMPLEMENTED tool of the contracts: status and
// confirm_database answer, every other tool is refused.
func (c ConnectOnly) Tools() []Tool {
	if c.Handoff == nil || c.Log == nil || c.Now == nil || c.LatestGuardVersion == nil {
		panic("agent: a connect-only agent needs its hand-off, a logger, a clock and the guard version")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]Tool, 0, len(contracts))
	for _, ct := range contracts {
		if ct.Status != mcpcontract.StatusImplemented {
			continue
		}
		var call func(context.Context, json.RawMessage) (any, error)
		switch ct.Name {
		case toolStatus:
			call = c.status
		case toolConfirmDatabase:
			call = c.confirm
		default:
			call = c.refused(ct.Name)
		}
		out = append(out, Tool{Name: ct.Name, Description: ct.Description, InputSchema: ct.InputSchema, Call: refuseAdminCredential(ct.Name, call)})
	}
	return out
}

func (c ConnectOnly) status(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, c.guide().Failure(toolStatus, nil, err)
	}
	return c.Status(ctx)
}

// refused answers every tool but status and confirm_database.
func (c ConnectOnly) refused(tool string) func(context.Context, json.RawMessage) (any, error) {
	return func(_ context.Context, raw json.RawMessage) (any, error) {
		st := c.Handoff.State()
		var err error = &SetupError{Code: st.Setup.Code, Fingerprint: st.Setup.Fingerprint, Expired: st.Expired, ConnectOnly: !st.Expired}
		if st.Phase == handoff.PhaseConfirm && st.Database != nil {
			err = &DatabaseNotConfirmedError{SetupID: st.Setup.SetupID, Database: *st.Database}
		}
		return nil, c.guide().Failure(tool, callArgs(raw), err)
	}
}

// confirmArgs are confirm_database's arguments.
type confirmArgs struct {
	SetupID  string          `json:"setupId" validate:"required,uuid"`
	Database handoff.Address `json:"database" validate:"required"`
	Answer   string          `json:"answer" validate:"required,oneof=YES NO"`
}

func (c ConnectOnly) confirm(ctx context.Context, raw json.RawMessage) (any, error) {
	var args confirmArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, c.guide().Failure(toolConfirmDatabase, nil, err)
	}
	ans, err := c.Handoff.Confirm(ctx, args.SetupID, args.Database, args.Answer == answerYes)
	switch {
	case errors.Is(err, handoff.ErrNotWaiting):
		return nil, c.guide().Failure(toolConfirmDatabase, callArgs(raw), &ArgumentError{Message: err.Error()})
	case err != nil:
		return nil, c.guide().Failure(toolConfirmDatabase, callArgs(raw), err)
	}
	return confirmResult(ans, c.Commands.OperatedBy(c.OperatedBy))
}

// confirmResult is confirm_database's result for ans.
func confirmResult(ans handoff.Answer, cmds Commands) (ConfirmResult, error) {
	b := NewSteps()
	out := ConfirmResult{State: confirmedState, Database: ans.Database}
	if ans.Confirmed {
		confirmedSteps(b)
	} else {
		out.State = refusedState
		out.PersonMessage = refusedResultSteps(b, cmds)
	}
	steps, err := b.Build()
	if err != nil {
		return ConfirmResult{}, err
	}
	out.NextSteps = steps
	out.PersonMessage = fitToSteps(out.PersonMessage, steps)
	return out, CheckPersonMessage(out.PersonMessage)
}

// Status is the status tool of a connect-only agent: the engine answers,
// the guard is UNKNOWN (no credential yet), and the setup says where the
// hand-off stands. While it waits for the address, a status call also
// collects.
func (c ConnectOnly) Status(ctx context.Context) (StatusReport, error) {
	st := c.Handoff.StatusCollect(ctx)
	cmds := c.Commands.OperatedBy(c.OperatedBy)
	base := c.PagesBase
	if base == "" {
		base = links.DefaultLocal
	}
	r := StatusReport{
		Agent: c.Name, OperatedBy: operatedBy(c.OperatedBy), Enforcement: enforcement(c.OperatedBy, c.SameUser),
		Engine: EngineStatus{Reachable: true, Build: buildinfo.Version, StartedBy: startedByEnum(c.StartedBy)},
		Guard:  GuardStatus{State: guardmodel.GuardUnknown, Build: c.LatestGuardVersion()},
		Pages:  PagesStatus{Served: c.PagesOrigin != "", URL: base},
	}
	if c.Vault != nil {
		v := c.Vault.VaultStatus()
		r.Vault = &v
	}
	ps := Problems{Cmds: cmds, ConnectBudget: c.ConnectBudget}
	r.Setup = connectOnlyProblems(st, &ps, c.Now())
	list, err := ps.Sorted()
	if err != nil {
		return StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

// connectOnlyProblems is status.setup for st, with its problem added to ps.
func connectOnlyProblems(st handoff.State, ps *Problems, now time.Time) SetupStatus {
	s := st.Setup
	v := setupFrom(&s, false, now)
	out := v.status
	switch {
	case st.Phase == handoff.PhaseRefused:
		v.addProblem(ps)
	case st.Phase == handoff.PhaseConfirm && st.Database != nil:
		db := *st.Database
		out.State, out.Fingerprint, out.Database = setupConfirmDatabase, "", &db
		ps.Add(problemConfirmDatabase, "the setup reached "+db.Name()+"; the person confirms it is their database before the agent uses it",
			func(b *Steps) string { return confirmDatabaseSteps(b, s.SetupID, db) })
	case st.Phase != handoff.PhaseWaiting:
		// Confirmed, or engine.json changed: the engine builds the agent
		// anew on what engine.json says now.
	case st.Expired:
		v.addProblem(ps)
	case st.Problem == handoff.ProblemAddressInvalid:
		ps.Add(problemAddressInvalid, "the database address the connect page handed over was refused",
			func(b *Steps) string { return addressInvalidSteps(b, ps.Cmds) })
	case st.Problem == handoff.ProblemTrustRootMismatch && st.Database != nil:
		db := *st.Database
		ps.Add(problemTrustRootMismatch, db.Name()+" presents another certificate authority to this machine than the one the person trusted on the connect page; nothing was pinned",
			func(b *Steps) string { return trustRootMismatchSteps(b, s.Code, ps.ConnectBudget, db) })
	case st.Problem == handoff.ProblemUnreachable && st.Database != nil:
		db := *st.Database
		ps.Add(problemUnreachableFromBot, "this machine cannot reach "+db.Name(),
			func(b *Steps) string { return unreachableFromBotSteps(b, s.Code, ps.ConnectBudget, db) })
	default:
		v.addProblem(ps)
		switch st.Problem {
		case handoff.ProblemClockSkew:
			ps.Add(problemClockSkew, "the clock of this machine is more than 5 minutes off; the address cannot be collected until it is set right", clockSkewSteps)
		case handoff.ProblemEngineAsRoot:
			ps.Add(problemEngineAsRoot, "the engine runs as root, so it does not collect this agent's database address", engineAsRootSteps)
		}
	}
	return out
}

// --- the served agent's confirm_database ---

// confirmDatabase answers confirm_database on an agent with no connect-only
// setup waiting: INVALID_ARGUMENT.
func (h handlers) confirmDatabase(_ context.Context, raw json.RawMessage) (any, error) {
	var args confirmArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return nil, &ArgumentError{Message: handoff.ErrNotWaiting.Error()}
}

// ConnectDatabaseName is how status names the database a credential
// connects to: "<host>:<port>, database <db>".
func ConnectDatabaseName(host string, port uint16, database string) string {
	if host == "" || strings.HasPrefix(host, "/") {
		return "database " + database
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))) + ", database " + database
}
