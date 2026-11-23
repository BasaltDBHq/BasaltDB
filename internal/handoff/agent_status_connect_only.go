package handoff

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

const (
	argSetupID  = "setupId"
	argDatabase = "database"
	AnswerYes   = "YES"
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

func connectOnlySteps(b *guidance.Steps, code, fingerprint string, budget int) (string, []toolresult.Link) {
	if code == "" {
		b.EndTurn("End your turn: a setup already started on the connect page may still finish.")
		b.CallTool(guidance.ToolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
		return connectOnlyExpiredHold, nil
	}
	if !guidance.SetupCode.MatchString(code) || fingerprint == "" {
		b.Fail(errors.New("a pending setup needs its code and fingerprint"))
		return "", nil
	}
	url := guidance.ConnectLink(code, budget)
	lead := "This agent's setup has not run yet, or its database's address did not reach the agent."
	if url == "" {
		b.OpenGivenLink("Open " + connectPortal + " on your own computer or phone, paste the setup code the agent gave you, and paste your database's connection string on that page only.")
	} else {
		b.OpenLink(url, guidance.ConnectOnlyStepText)
	}
	b.EndTurn("End your turn: the person acts on the connect page next.")
	b.CallTool(guidance.ToolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	if url == "" {
		return lead + " Open " + connectPortal + ", paste the setup code the agent gave you, check that it shows the setup fingerprint " + fingerprint +
			", and paste your database's connection string there only, never in this chat. If you already approved it, approve once more.", nil
	}
	return guidance.ConnectOnlyMessage(lead+" If you already approved it, open the same link and approve once more.", url, fingerprint)
}

// ConfirmDatabaseSteps: the agent asks the person whether db is their
// database, ends its turn, and calls confirm_database with their answer.
// The engine fills in setupId and database, never answer.
func ConfirmDatabaseSteps(b *guidance.Steps, setupID string, db setupcode.Address) string {
	b.AskPerson("Ask the person exactly: The setup points me at " + db.Name() + ". Is that your database?")
	b.EndTurn("End your turn: the person answers next.")
	b.CallTool(guidance.ToolConfirmDatabase, map[string]any{argSetupID: setupID, argDatabase: databaseArg(db)},
		"Call this with answer set to the person's own yes (YES) or no (NO) about that database. Never answer for them.")
	return "The setup points the agent at " + db.Name() + ". The agent asks you in the chat whether that is your database, and uses it only after you say yes. " +
		"If it is not the one you pasted on the connect page, say no."
}

// databaseArg is db as confirm_database takes it.
func databaseArg(db setupcode.Address) map[string]any {
	out := map[string]any{"host": db.Host, "port": db.Port, "database": db.Database}
	if db.SupabaseRef != "" {
		out["supabaseRef"] = db.SupabaseRef
	}
	return out
}

// databaseRefusedSteps: a recovery code, made on the engine's machine.
func databaseRefusedSteps(b *guidance.Steps, cmds guidance.Commands) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "You said the database the setup reached is not yours, so the agent never logged in there and forgot its address and password. " +
		"The agent gives you a new link to set it up again; paste your own database's connection string there."
}

// addressInvalidSteps: the address the page handed over was refused; the
// next basalt init --remote forgets the setup and makes a recovery code.
func addressInvalidSteps(b *guidance.Steps, cmds guidance.Commands) string {
	b.AskPerson("Tell the person the database address the connect page handed over was refused, so you did not use it.")
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The database address the connect page handed over was refused, so the agent did not use it. The agent gives you a new link: " +
		"paste your database's connection string there again."
}

// setupNotFoundSteps: the database the person confirmed does not record
// the setup; a new code.
func setupNotFoundSteps(b *guidance.Steps, cmds guidance.Commands, database string) string {
	where := "the database the agent connected to"
	if database != "" {
		where = database
	}
	b.AskPerson("Tell the person " + guidance.Shown(where, guidance.MaxTableChars) + " does not record this agent's setup, and that you make a new setup code.")
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The database you confirmed, " + guidance.Shown(where, guidance.MaxTableChars) + ", does not record this agent's setup. The agent gives you a new link to run the setup there."
}

// clockSkewSteps: the clock of the bot's machine is off.
func clockSkewSteps(b *guidance.Steps) string {
	b.AskPerson("Tell the person the clock of this machine is more than 5 minutes off, so the agent cannot collect its database's address until it is set right.")
	b.EndTurn("End your turn: the person fixes the clock next.")
	return "The clock of the agent's machine is more than 5 minutes off, so the agent cannot collect your database's address. Set the machine's clock right (turn on automatic time), then tell the agent."
}

// engineAsRootSteps: the engine was started as root; it
// must run as the agent's OS user to collect the address.
func engineAsRootSteps(b *guidance.Steps) string {
	b.AskPerson("Tell the person the engine runs as root, so it cannot pick up this agent's database address until it is restarted as the engine's user (the owner of its state directory).")
	b.EndTurn("End your turn: the person restarts the engine next.")
	return "The engine on the agent's machine runs as root, so it cannot pick up this agent's database address. " +
		"Restart it as the engine's user (the owner of its state directory), then tell the agent."
}

// unreachableFromBotSteps: the bot's machine cannot reach the collected
// database; the person runs the same link with a string it can reach.
func unreachableFromBotSteps(b *guidance.Steps, code string, budget int, db setupcode.Address) string {
	url := guidance.ConnectLink(code, budget)
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
	b.CallTool(guidance.ToolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	// The link is in the step; the message names the fix only.
	return "The setup ran, but the agent's machine cannot reach " + db.Name() + ". To fix it, " + fix + ", then tell the agent."
}

// trustRootMismatchSteps: the collected database presents another
// certificate authority to the bot's machine than the one the person
// trusted on the connect page; nothing was pinned.
func trustRootMismatchSteps(b *guidance.Steps, code string, budget int, db setupcode.Address) string {
	url := guidance.ConnectLink(code, budget)
	text := "Open the same link again: the page reads the database's certificate again. Check it against your provider's console before you trust it."
	if url == "" {
		b.OpenGivenLink(text)
	} else {
		b.OpenLink(url, text)
	}
	b.EndTurn("End your turn: the person acts next.")
	b.CallTool(guidance.ToolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
	return "The setup ran, but " + db.Name() + " shows the agent's machine another certificate authority than the one you trusted on the connect page, so the agent trusts nothing and does not sign in. " +
		"Open the same link again and check the certificate against your provider's console. If it changes again, something between the agent's machine and your database may be in the way."
}

// ConfirmResult is confirm_database's result.
type ConfirmResult struct {
	State         string                `json:"state"`
	Database      setupcode.Address     `json:"database"`
	PersonMessage string                `json:"personMessage,omitempty"`
	Links         []toolresult.Link     `json:"links,omitempty"`
	NextSteps     []toolresult.NextStep `json:"nextSteps"`
}

// confirmedSteps: the engine restarts the agent on its credential; status
// says whether the database records the setup.
func confirmedSteps(b *guidance.Steps) string {
	b.CallTool(guidance.ToolStatus, map[string]any{}, "Call status: it shows whether the database records the setup, and the agent works once it does.")
	return ""
}

// refusedResultSteps: the address and the password are gone; a new code.
func refusedResultSteps(b *guidance.Steps, cmds guidance.Commands) string {
	return databaseRefusedSteps(b, cmds)
}

// Handoff is the engine's connect-only setup (handoff.Pending).
type Handoff interface {
	State() State
	StatusCollect(ctx context.Context) State
	Confirm(ctx context.Context, setupID string, db setupcode.Address, yes bool) (Answer, error)
}

// ConfirmArgs are confirm_database's arguments.
type ConfirmArgs struct {
	SetupID  string            `json:"setupId" validate:"required,uuid"`
	Database setupcode.Address `json:"database" validate:"required"`
	Answer   string            `json:"answer" validate:"required,oneof=YES NO"`
}

// NewConfirmResult is confirm_database's result for ans.
func NewConfirmResult(ans Answer, cmds guidance.Commands) (ConfirmResult, error) {
	b := guidance.NewSteps()
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
	out.PersonMessage = guidance.FitToSteps(out.PersonMessage, steps)
	return out, guidance.CheckPersonMessage(out.PersonMessage)
}

// ConnectOnlyProblems is status.setup for st, with its problem added to ps.
func ConnectOnlyProblems(st State, ps *guidance.Problems, now time.Time) guidance.SetupStatus {
	s := st.Setup
	v := SetupFrom(&s, false, now)
	out := v.Status
	switch {
	case st.Phase == PhaseRefused:
		v.AddProblem(ps)
	case st.Phase == PhaseConfirm && st.Database != nil:
		db := *st.Database
		out.State, out.Fingerprint, out.Database = setupConfirmDatabase, "", &db
		ps.Add(problemConfirmDatabase, "the setup reached "+db.Name()+"; the person confirms it is their database before the agent uses it",
			func(b *guidance.Steps) string { return ConfirmDatabaseSteps(b, s.SetupID, db) })
	case st.Phase != PhaseWaiting:
		// Confirmed, or engine.json changed: the engine builds the agent
		// anew on what engine.json says now.
	case st.Expired:
		v.AddProblem(ps)
	case st.Problem == ProblemAddressInvalid:
		ps.Add(ProblemAddressInvalid, "the database address the connect page handed over was refused",
			func(b *guidance.Steps) string { return addressInvalidSteps(b, ps.Cmds) })
	case st.Problem == ProblemTrustRootMismatch && st.Database != nil:
		db := *st.Database
		ps.Add(ProblemTrustRootMismatch, db.Name()+" presents another certificate authority to this machine than the one the person trusted on the connect page; nothing was pinned",
			func(b *guidance.Steps) string { return trustRootMismatchSteps(b, s.Code, ps.ConnectBudget, db) })
	case st.Problem == ProblemUnreachable && st.Database != nil:
		db := *st.Database
		ps.Add(problemUnreachableFromBot, "this machine cannot reach "+db.Name(),
			func(b *guidance.Steps) string { return unreachableFromBotSteps(b, s.Code, ps.ConnectBudget, db) })
	default:
		v.AddProblem(ps)
		switch st.Problem {
		case ProblemClockSkew:
			ps.Add(ProblemClockSkew, "the clock of this machine is more than 5 minutes off; the address cannot be collected until it is set right", clockSkewSteps)
		case ProblemEngineAsRoot:
			ps.Add(ProblemEngineAsRoot, "the engine runs as root, so it does not collect this agent's database address", engineAsRootSteps)
		}
	}
	return out
}

// ConnectDatabaseName is how status names the database a credential
// connects to: "<host>:<port>, database <db>".
func ConnectDatabaseName(host string, port uint16, database string) string {
	if host == "" || strings.HasPrefix(host, "/") {
		return "database " + database
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))) + ", database " + database
}
