package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
)

// The contract's connect-only fixture (api/mcp/setup/setup-code.fixtures.json,
// "connect-only install of all tables").
const (
	connectOnlyFixture = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDg6xTUmHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8.mvDCHA"
	caseSetupID        = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
	caseFingerprint    = "734b aaea 804e 1065 4148"
)

// caseDatabase is a collected database through Supabase's pooler.
var caseDatabase = handoff.Address{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}

// connectOnlySetup is the fixture's pending setup in engine.json.
func connectOnlySetup(expires time.Time) config.Setup {
	return config.Setup{
		SetupID: caseSetupID, Kind: guard.SetupInstall, GuardVersion: guard.LatestVersion(),
		ExpiresAt: expires.UTC().Format(time.RFC3339), Code: connectOnlyFixture, Fingerprint: caseFingerprint, AwaitingAddress: true,
	}
}

type fakeHandoff struct {
	st      handoff.State
	err     error
	asked   []bool
	statusN int
}

func (f *fakeHandoff) State() handoff.State { return f.st }

func (f *fakeHandoff) StatusCollect(context.Context) handoff.State {
	f.statusN++
	return f.st
}

func (f *fakeHandoff) Confirm(_ context.Context, id string, db handoff.Address, yes bool) (handoff.Answer, error) {
	f.asked = append(f.asked, yes)
	if f.err != nil {
		return handoff.Answer{}, f.err
	}
	if id != f.st.Setup.SetupID || f.st.Database == nil || db != *f.st.Database {
		return handoff.Answer{}, handoff.ErrNotWaiting
	}
	return handoff.Answer{Confirmed: yes, Database: db}, nil
}

func connectOnlyServer(t *testing.T, operatedBy string, h Handoff) ConnectOnly {
	t.Helper()
	cmds, err := NewCommands("bot", "", "linux")
	require.NoError(t, err)
	return ConnectOnly{
		Name: "bot", Commands: cmds, OperatedBy: operatedBy, PagesBase: "https://portal.basaltvault.app",
		ConnectBudget: links.DefaultBudget, Handoff: h,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}
}

// connectOnlyStatusOf is ConnectOnly's status for the hand-off state st.
func connectOnlyStatusOf(operatedBy string, st handoff.State) func(t *testing.T) StatusReport {
	return func(t *testing.T) StatusReport {
		t.Helper()
		r, err := connectOnlyServer(t, operatedBy, &fakeHandoff{st: st}).Status(context.Background())
		require.NoError(t, err)
		return r
	}
}

func connectOnlyStatusCases(operatedBy string) map[string]statusCase {
	soon := statusNow.Add(time.Hour)
	waiting := connectOnlySetup(soon)
	db := caseDatabase
	refused := waiting
	refused.AwaitingAddress, refused.Refused = false, true
	confirmed := waiting
	confirmed.AwaitingAddress = false
	return map[string]statusCase{
		problemConfirmDatabase: {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{Setup: waiting, Phase: handoff.PhaseConfirm, Database: &db})},
		problemDatabaseRefused: {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{Setup: refused, Phase: handoff.PhaseRefused})},
		problemUnreachableFromBot: {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{
			Setup: waiting, Phase: handoff.PhaseWaiting, Problem: handoff.ProblemUnreachable, Database: &db,
		})},
		problemTrustRootMismatch: {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{
			Setup: waiting, Phase: handoff.PhaseWaiting, Problem: handoff.ProblemTrustRootMismatch, Database: &db,
		})},
		problemAddressInvalid: {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{Setup: waiting, Phase: handoff.PhaseWaiting, Problem: handoff.ProblemAddressInvalid})},
		problemClockSkew:      {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{Setup: waiting, Phase: handoff.PhaseWaiting, Problem: handoff.ProblemClockSkew})},
		problemEngineAsRoot:   {state: guard.GuardUnknown, report: connectOnlyStatusOf(operatedBy, handoff.State{Setup: waiting, Phase: handoff.PhaseWaiting, Problem: handoff.ProblemEngineAsRoot})},
		problemSetupNotFound: {state: guard.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return operatedStatus(&fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}, 1, &confirmed, operatedBy)(t)
		}},
	}
}

func confirmResultCases() map[string]resultCase {
	build := func(yes bool) func(*testing.T, *Service) (string, []mcp.Link, []mcp.NextStep) {
		return func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
			t.Helper()
			r, err := confirmResult(handoff.Answer{Confirmed: yes, Database: caseDatabase}, s.Commands)
			require.NoError(t, err)
			return r.PersonMessage, r.Links, r.NextSteps
		}
	}
	args := map[string]any{argSetupID: caseSetupID, argDatabase: databaseArg(caseDatabase), argAnswer: answerYes}
	return map[string]resultCase{
		resultKey(toolConfirmDatabase, confirmedState): {tool: toolConfirmDatabase, args: args, build: build(true)},
		resultKey(toolConfirmDatabase, refusedState):   {tool: toolConfirmDatabase, args: args, build: build(false)},
	}
}

// While the address is awaited, status shows the connect-only setup with
// the connect link and the waiting message, and collects; every tool but
// status and confirm_database answers SETUP_PENDING with one step: status.
func TestConnectOnlyWaitingServesOnlyStatus(t *testing.T) {
	t.Parallel()
	h := &fakeHandoff{st: handoff.State{Setup: connectOnlySetup(statusNow.Add(time.Hour)), Phase: handoff.PhaseWaiting}}
	c := connectOnlyServer(t, mcpcontract.OperatedByAgent, h)
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, c.Tools()...)

	r, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, h.statusN, "status collects")
	require.Equal(t, setupPending, r.Setup.State)
	require.True(t, r.Setup.ConnectOnly)
	require.Equal(t, caseFingerprint, r.Setup.Fingerprint)
	require.True(t, r.Engine.Reachable)
	require.False(t, r.Ready)
	p := findProblem(t, r, problemSetupNotRun)
	require.Equal(t, connectOnlyWaiting, p.Message)
	require.Equal(t, mcp.ActionOpenLink, p.NextSteps[0].Action)
	require.True(t, strings.HasPrefix(p.NextSteps[0].URL, "https://portal.basaltvault.app/connect#basalt-setup.1."))
	require.NotContains(t, p.PersonMessage, "basalt init --setup-code", "no laptop command for a connect-only code")
	requireStatusSchema(t, statusToolContract(t), r)

	for _, tool := range c.Tools() {
		if tool.Name == toolStatus || tool.Name == toolConfirmDatabase {
			continue
		}
		body, isError := serveCall(t, srv, tool.Name, map[string]any{})
		require.True(t, isError, tool.Name)
		require.Equal(t, CodeUnavailable, body["code"], tool.Name)
		require.Equal(t, reasonSetupPending, body["reason"], tool.Name)
		require.Equal(t, []mcpcontract.StepKind{{Actor: mcp.ActorAgent, Action: mcp.ActionCallTool}}, steps(t, body), tool.Name)
	}
	body, isError := serveCall(t, srv, toolConfirmDatabase, map[string]any{
		argSetupID: caseSetupID, argDatabase: databaseArg(caseDatabase), argAnswer: answerYes,
	})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"], "nothing waits for confirmation yet")
	require.Equal(t, []bool{true}, h.asked)
}

// After the code expires, status still waits through the collect window and
// does not reprint the expired link. After the window it is SETUP_EXPIRED.
func TestConnectOnlyWaitingAfterExpiryOmitsTheCode(t *testing.T) {
	t.Parallel()
	h := &fakeHandoff{st: handoff.State{Setup: connectOnlySetup(statusNow.Add(-time.Minute)), Phase: handoff.PhaseWaiting}}
	c := connectOnlyServer(t, mcpcontract.OperatedByAgent, h)
	r, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, setupPending, r.Setup.State)
	require.True(t, r.Setup.ConnectOnly)
	require.Empty(t, r.Setup.Fingerprint)
	p := findProblem(t, r, problemSetupNotRun)
	require.Equal(t, connectOnlyExpiredHold, p.Message)
	require.NotEqual(t, mcp.ActionOpenLink, p.NextSteps[0].Action)
	require.NotContains(t, p.PersonMessage, connectOnlyFixture)
	require.NotContains(t, p.PersonMessage, caseFingerprint)
	require.NotContains(t, p.Message, connectOnlyFixture)
}

func TestConnectOnlyAfterTheCollectWindowIsExpired(t *testing.T) {
	t.Parallel()
	h := &fakeHandoff{st: handoff.State{Setup: connectOnlySetup(statusNow.Add(-31 * time.Minute)), Phase: handoff.PhaseWaiting}}
	c := connectOnlyServer(t, mcpcontract.OperatedByAgent, h)
	r, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, setupExpired, r.Setup.State)
	require.Empty(t, r.Setup.Fingerprint)
	p := findProblem(t, r, problemSetupExpired)
	require.NotContains(t, p.PersonMessage, connectOnlyFixture)
}

// Once the probe passed, status names the database and every other tool
// answers DATABASE_NOT_CONFIRMED with the question and the filled-in call.
func TestConnectOnlyConfirmDatabase(t *testing.T) {
	t.Parallel()
	db := caseDatabase
	h := &fakeHandoff{st: handoff.State{Setup: connectOnlySetup(statusNow.Add(time.Hour)), Phase: handoff.PhaseConfirm, Database: &db}}
	c := connectOnlyServer(t, mcpcontract.OperatedByAgent, h)
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, c.Tools()...)

	r, err := c.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, setupConfirmDatabase, r.Setup.State)
	require.Equal(t, &db, r.Setup.Database)
	requireStatusSchema(t, statusToolContract(t), r)
	p := findProblem(t, r, problemConfirmDatabase)
	require.Contains(t, p.NextSteps[0].Text, "The setup points me at Supabase project abcdefghijklmnopqrst, database postgres. Is that your database?")
	call := p.NextSteps[2]
	require.Equal(t, toolConfirmDatabase, call.Tool)
	require.Equal(t, caseSetupID, call.Arguments[argSetupID])
	require.NotContains(t, call.Arguments, argAnswer, "the engine never fills in the answer")

	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, reasonDatabaseNotConfirmed, body["reason"])

	// Another setupId or another database is refused: an answer never
	// confirms a database the person was not asked about.
	other := databaseArg(caseDatabase)
	other["database"] = "other"
	body, isError = serveCall(t, srv, toolConfirmDatabase, map[string]any{argSetupID: caseSetupID, argDatabase: other, argAnswer: answerYes})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"])
	body, isError = serveCall(t, srv, toolConfirmDatabase, map[string]any{argSetupID: caseSetupID, argDatabase: databaseArg(caseDatabase), argAnswer: "MAYBE"})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"])

	body, isError = serveCall(t, srv, toolConfirmDatabase, map[string]any{argSetupID: caseSetupID, argDatabase: databaseArg(caseDatabase), argAnswer: answerNo})
	require.False(t, isError, "%v", body)
	require.Equal(t, refusedState, body["state"])
	require.NotEmpty(t, body["personMessage"])
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), toolConfirmDatabase)
	require.True(t, ok)
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.NoError(t, validateSchema(tool.OutputSchema, body), string(raw))
}

func statusToolContract(t *testing.T) mcpcontract.Tool {
	t.Helper()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), toolStatus)
	require.True(t, ok)
	return tool
}

// A served agent with no connect-only setup answers confirm_database with
// INVALID_ARGUMENT, before any admission.
func TestConfirmDatabaseOnAServedAgent(t *testing.T) {
	t.Parallel()
	s := NewService(deps())
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "test"}, Tools(s)...)
	body, isError := serveCall(t, srv, toolConfirmDatabase, map[string]any{argSetupID: caseSetupID, argDatabase: databaseArg(caseDatabase), argAnswer: answerYes})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"])
}

// The shim reports a refused connect-only setup from engine.json, and a
// waiting one with its connect link.
func TestEngineDownReportsAConnectOnlySetup(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux")
	require.NoError(t, err)
	waiting := connectOnlySetup(statusNow.Add(time.Hour))
	refused := waiting
	refused.AwaitingAddress, refused.Refused = false, true
	for _, tc := range []struct {
		setup config.Setup
		state string
		code  string
	}{
		{waiting, setupPending, problemSetupNotRun},
		{refused, setupRefused, problemDatabaseRefused},
	} {
		cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Agents: []config.Agent{{
			Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential), Setup: &tc.setup,
		}}}
		r, err := EngineDownStatus("bot", cmds, cfg, nil, "test", statusNow)
		require.NoError(t, err)
		require.Equal(t, tc.state, r.Setup.State)
		require.True(t, r.Setup.ConnectOnly)
		findProblem(t, r, tc.code)
	}
}
