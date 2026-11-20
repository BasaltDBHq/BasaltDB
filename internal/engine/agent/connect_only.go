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
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/handoff"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
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
	// reasonDatabaseNotConfirmed: the engine collected the database's
	// address and the person has not confirmed it yet.
	reasonDatabaseNotConfirmed = "DATABASE_NOT_CONFIRMED"
	// The states of confirm_database's result.
	confirmedState = "CONFIRMED"
	refusedState   = "REFUSED"
)

// connectOnlyWaiting is status's message while a connect-only setup waits
// for its address: the engine cannot tell a setup not run yet from an
// address the service lost.
const connectOnlyWaiting = "Waiting for the setup on the connect page. If you already approved it there, open the same link again and approve once more: your bot will connect."

// connectPortal is where a connect-only code is pasted when its link does
// not fit the link budget.
const connectPortal = "portal.basaltvault.app/connect"

// connectOnlySteps: the person opens the connect link (the code pasted at
// the portal when the link does not fit), pastes the database's connection
// string there only, and the page waits for the bot; the agent ends its
// turn and checks status after.
func connectOnlySteps(b *Steps, code, fingerprint string, budget int) (string, []mcp.Link) {
	if !setupCode.MatchString(code) || fingerprint == "" {
		b.fail(errors.New("a pending setup needs its code and fingerprint"))
		return "", nil
	}
	url := ConnectLink(code, budget)
	lead := "This agent's setup has not run yet, or its database's address did not reach the agent."
	if url == "" {
		b.OpenGivenLink("", "Open "+connectPortal+" on your own computer or phone, paste the setup code the agent gave you, and paste your database's connection string on that page only.")
	} else {
		b.OpenLink(url, "", ConnectOnlyStepText)
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
	b.MachineCommand(cmds, cmds.InitRemote(""), "Make a new setup code on the agent's machine with this, then follow the steps it prints.",
		"Run this once to make a new setup code, then show the person its personMessage and follow its nextSteps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "You said the database the setup reached is not yours, so the agent never logged in there and forgot its address and password. " +
		"The agent gives you a new link to set it up again; paste your own database's connection string there."
}

// addressInvalidSteps: the address the page handed over was refused; a
// recovery code with --forget.
func addressInvalidSteps(b *Steps, cmds Commands) string {
	b.AskPerson("Tell the person the database address the connect page handed over was refused, so you did not use it.")
	b.MachineCommand(cmds, cmds.InitRemote("--forget"), "Make a new setup code on the agent's machine with this, then follow the steps it prints.",
		"Run this once to make a new setup code, then show the person its personMessage and follow its nextSteps.")
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
	b.MachineCommand(cmds, cmds.InitRemote("--new-code"), "Make a new setup code on the agent's machine with this, then follow the steps it prints.",
		"Run this once to make a new setup code, then show the person its personMessage and follow its nextSteps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The database you confirmed, " + shown(where, maxTableChars) + ", does not record this agent's setup. The agent gives you a new link to run the setup there."
}

// clockSkewSteps: the clock of the bot's machine is off.
func clockSkewSteps(b *Steps) string {
	b.AskPerson("Tell the person the clock of this machine is more than 5 minutes off, so the agent cannot collect its database's address until it is set right.")
	b.EndTurn("End your turn: the person fixes the clock next.")
	return "The clock of the agent's machine is more than 5 minutes off, so the agent cannot collect your database's address. Set the machine's clock right (turn on automatic time), then tell the agent."
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
		b.OpenGivenLink("", text)
	} else {
		b.OpenLink(url, "", text)
	}
	b.EndTurn("End your turn: the person acts next.")
	b.CallTool(toolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	// The link is in the step; the message names the fix only.
	return "The setup ran, but the agent's machine cannot reach " + db.Name() + ". To fix it, " + fix + ", then tell the agent."
}

// DatabaseNotConfirmedError refuses a tool while the collected database
// waits for the person's confirmation (UNAVAILABLE DATABASE_NOT_CONFIRMED).
type DatabaseNotConfirmedError struct {
	SetupID  string
	Database handoff.Address
}

func (e *DatabaseNotConfirmedError) Error() string {
	return "the agent's database waits for the person's confirmation; no tool but status and confirm_database works until then"
}

// --- the result of confirm_database ---

// ConfirmResult is confirm_database's result.
type ConfirmResult struct {
	State         string          `json:"state"`
	Database      handoff.Address `json:"database"`
	PersonMessage string          `json:"personMessage,omitempty"`
	Links         []mcp.Link      `json:"links,omitempty"`
	NextSteps     []NextStep      `json:"nextSteps"`
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
	PagesBase  string
	// PagesOrigin is the origin of the local pages when served.
	PagesOrigin   string
	ConnectBudget int
	Vault         VaultReporter
	Handoff       Handoff
	Log           *slog.Logger
	Now           func() time.Time
}

// guide is a Service with only what the error guidance reads.
func (c ConnectOnly) guide() *Service {
	return &Service{Deps: Deps{Name: c.Name, Commands: c.Commands.OperatedBy(c.OperatedBy), ConnectBudget: c.ConnectBudget, Log: c.Log, Now: c.Now}}
}

// Tools are every IMPLEMENTED tool of the contracts: status and
// confirm_database answer, every other tool is refused.
func (c ConnectOnly) Tools() []mcp.Tool {
	if c.Handoff == nil || c.Log == nil || c.Now == nil {
		panic("agent: a connect-only agent needs its hand-off, a logger and a clock")
	}
	contracts := mcpcontract.MustLoad()
	out := make([]mcp.Tool, 0, len(contracts))
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
		out = append(out, mcp.Tool{Name: ct.Name, Description: ct.Description, InputSchema: ct.InputSchema, Call: refuseAdminCredential(ct.Name, call)})
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
		Engine: EngineStatus{Reachable: true, Build: buildinfo.Version},
		Guard:  GuardStatus{State: guard.GuardUnknown, Build: guard.LatestVersion()},
		Pages:  PagesStatus{Served: c.PagesOrigin != "", URL: base},
	}
	if c.Vault != nil {
		v := c.Vault.VaultStatus()
		r.Vault = &v
	}
	ps := problems{cmds: cmds, connectBudget: c.ConnectBudget}
	r.Setup = connectOnlyProblems(st, &ps, c.Now())
	list, err := ps.sorted()
	if err != nil {
		return StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

// connectOnlyProblems is status.setup for st, with its problem added to ps.
func connectOnlyProblems(st handoff.State, ps *problems, now time.Time) SetupStatus {
	s := st.Setup
	v := setupFrom(&s, false, now)
	out := v.status
	switch {
	case st.Phase == handoff.PhaseRefused:
		v.addProblem(ps)
	case st.Phase == handoff.PhaseConfirm && st.Database != nil:
		db := *st.Database
		out.State, out.Fingerprint, out.Database = setupConfirmDatabase, "", &db
		ps.add(problemConfirmDatabase, "the setup reached "+db.Name()+"; the person confirms it is their database before the agent uses it",
			func(b *Steps) string { return confirmDatabaseSteps(b, s.SetupID, db) })
	case st.Phase != handoff.PhaseWaiting:
		// Confirmed, or engine.json changed: the engine builds the agent
		// anew on what engine.json says now.
	case st.Expired:
		v.addProblem(ps)
	case st.Problem == handoff.ProblemAddressInvalid:
		ps.add(problemAddressInvalid, "the database address the connect page handed over was refused",
			func(b *Steps) string { return addressInvalidSteps(b, ps.cmds) })
	case st.Problem == handoff.ProblemUnreachable && st.Database != nil:
		db := *st.Database
		ps.add(problemUnreachableFromBot, "this machine cannot reach "+db.Name(),
			func(b *Steps) string { return unreachableFromBotSteps(b, s.Code, ps.connectBudget, db) })
	default:
		v.addProblem(ps)
		if st.Problem == handoff.ProblemClockSkew {
			ps.add(problemClockSkew, "the clock of this machine is more than 5 minutes off; the address cannot be collected until it is set right", clockSkewSteps)
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
