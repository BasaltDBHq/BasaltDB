package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// This file is the contract test of the status tool (CONTRACT.md, MCP tools,
// status) and of degraded mode: every problem of the catalog has a case,
// every case's report validates against status.json's outputSchema, its
// problem obeys the catalog, and nothing in it names the credential file.

// statusCredential is a credential file path no status output may hold.
const statusCredential = "/etc/basalt/agents/bot.url"

// fakeProbe is a Probe with a fixed answer.
type fakeProbe struct {
	st       guard.Status
	err      error
	recorded bool
	// recordedErr fails SetupRecorded.
	recordedErr error
	latest      *guard.AgentSetup
	// ledger is LedgerBytes's answer; ledgerErr fails it.
	ledger    int64
	ledgerErr error
}

func (p *fakeProbe) LedgerBytes(context.Context) (int64, error) { return p.ledger, p.ledgerErr }

func (p *fakeProbe) GuardStatus(context.Context) (guard.Status, error) { return p.st, p.err }

func (p *fakeProbe) SetupRecorded(context.Context, uuid.UUID) (bool, error) {
	return p.recorded, p.recordedErr
}

func (p *fakeProbe) LatestSetup(context.Context) (guard.AgentSetup, bool, error) {
	if p.latest == nil {
		return guard.AgentSetup{}, false, nil
	}
	return *p.latest, true, nil
}

// keys answers Passkeys with n passkeys.
type keys struct {
	ApprovalStore
	n int
}

func (k keys) Passkeys(context.Context) ([]passkey.Credential, error) {
	return make([]passkey.Credential, k.n), nil
}

func guardAt(state string, missingBreaking, missingNonBreaking []int) guard.Status {
	b := guard.LatestVersion()
	installed := b
	if state == guard.GuardNewer {
		installed = b + 1
	}
	return guard.Status{State: state, Installed: installed, Build: b, MissingBreaking: missingBreaking, MissingNonBreaking: missingNonBreaking}
}

var statusNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// testSetupCode and testFingerprint stand for a pending setup code (in the
// codec's alphabet) and its fingerprint.
const (
	testSetupCode   = "basalt-setup.1.eJzLSM3JyVcozy_KSQEAGgQEXQ.Ab3_x9"
	testFingerprint = "a1b2 c3d4 e5f6 0718 293a"
)

func pendingSetup(kind string, expires time.Time) *config.Setup {
	return &config.Setup{
		SetupID: "0193a4c2-7d1e-7c3a-9f00-0000000000e5", Kind: kind, GuardVersion: guard.LatestVersion(),
		ExpiresAt: expires.UTC().Format(time.RFC3339), Code: testSetupCode, Fingerprint: testFingerprint,
	}
}

// statusCase builds a report for one situation.
type statusCase struct {
	report func(t *testing.T) StatusReport
	// state is the guard state the report must give.
	state string
}

func engineStatus(probe *fakeProbe, passkeys int, setup *config.Setup) func(t *testing.T) StatusReport {
	return operatedStatus(probe, passkeys, setup, "")
}

// operatedStatus is engineStatus on an engine whose operatedBy is operatedBy.
func operatedStatus(probe *fakeProbe, passkeys int, setup *config.Setup, operatedBy string) func(t *testing.T) StatusReport {
	return operatedStatusWith(probe, passkeys, setup, operatedBy, "", []string{"--agent=bot", "--write=public.leads"})
}

// operatedStatusWith is operatedStatus with the engine config at configPath
// and the flags init saved.
func operatedStatusWith(probe *fakeProbe, passkeys int, setup *config.Setup, operatedBy, configPath string, saved []string) func(t *testing.T) StatusReport {
	return func(t *testing.T) StatusReport {
		t.Helper()
		d := deps()
		d.OperatedBy = operatedBy
		d.Probe = probe
		d.Approvals = keys{n: passkeys}
		d.Setup = setup
		d.Now = func() time.Time { return statusNow }
		// The credential file is at init's default, so no saved flag names it
		// (a saved --credential-file stays in init commands, AE-15).
		cmds, err := NewCommands("bot", configPath, "linux", saved)
		require.NoError(t, err)
		d.Commands = cmds
		r, err := NewService(d).Status(context.Background())
		require.NoError(t, err)
		return r
	}
}

func statusCases() map[string]statusCase { return statusCasesFor("") }

// statusCasesFor are the status cases on an engine whose operatedBy is
// operatedBy.
func statusCasesFor(operatedBy string) map[string]statusCase {
	ok := guardAt(guard.GuardOK, nil, nil)
	soon, past := statusNow.Add(time.Hour), statusNow.Add(-time.Hour)
	engineStatus := func(probe *fakeProbe, passkeys int, setup *config.Setup) func(t *testing.T) StatusReport {
		return operatedStatus(probe, passkeys, setup, operatedBy)
	}
	return map[string]statusCase{
		problemEngineUnreachable: {state: guard.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			cmds, err := NewCommands("bot", "", "linux", nil)
			require.NoError(t, err)
			cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: operatedBy, Agents: []config.Agent{{Name: "bot", OSUser: "bot", CredentialFile: statusCredential}}}
			r, err := EngineDownStatus("bot", cmds, cfg, "test", statusNow)
			require.NoError(t, err)
			return r
		}},
		problemDatabaseUnreachable: {state: guard.GuardUnknown, report: engineStatus(&fakeProbe{err: fmt.Errorf("dial %s: %w", statusCredential, context.DeadlineExceeded)}, 1, nil)},
		problemTooManyConnections: {state: guard.GuardUnknown, report: engineStatus(&fakeProbe{err: &pgconn.PgError{
			Code:    "53300",
			Message: `too many connections for role "basalt_agent_bot"`,
		}}, 1, nil)},
		problemCredentialRejected: {state: guard.GuardUnknown, report: engineStatus(&fakeProbe{err: &pgconn.PgError{
			Code:    "28P01",
			Message: "password authentication failed (" + statusCredential + ")",
		}}, 1, nil)},
		problemGuardMissing:       {state: guard.GuardMissing, report: engineStatus(&fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}, 1, nil)},
		problemGuardOutdated:      {state: guard.GuardOutdated, report: engineStatus(&fakeProbe{st: guardAt(guard.GuardOutdated, []int{guard.LatestVersion()}, nil)}, 1, nil)},
		problemUpgradeAvailable:   {state: guard.GuardUpgradeAvailable, report: engineStatus(&fakeProbe{st: guardAt(guard.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, 1, nil)},
		problemNoPasskey:          {state: guard.GuardOK, report: engineStatus(&fakeProbe{st: ok}, 0, nil)},
		problemSetupNotRun:        {state: guard.GuardMissing, report: engineStatus(&fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}, 0, pendingSetup(guard.SetupInstall, soon))},
		problemSetupExpired:       {state: guard.GuardUnknown, report: engineStatus(&fakeProbe{err: &pgconn.PgError{Code: "28000", Message: "role does not exist"}}, 0, pendingSetup(guard.SetupInstall, past))},
		problemSetupChangePending: {state: guard.GuardOK, report: engineStatus(&fakeProbe{st: ok}, 1, pendingSetup(guard.SetupAgent, soon))},
		problemLockFileUnusable: {state: guard.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return lockTroubleStatus(t, operatedBy)
		}},
	}
}

func TestEveryStatusProblemHasACase(t *testing.T) {
	t.Parallel()
	cases := statusCases()
	var missing []string
	for _, p := range catalogOf(t).Problems {
		if _, ok := cases[p.Code]; !ok {
			missing = append(missing, p.Code)
		}
	}
	require.Empty(t, missing, "catalog problems without a case in statusCases")
	require.Len(t, cases, len(catalogOf(t).Problems), "cases without a catalog problem")
}

func TestEveryStatusProblemObeysTheCatalog(t *testing.T) {
	t.Parallel()
	statusTool, ok := mcpcontract.Find(mcpcontract.MustLoad(), toolStatus)
	require.True(t, ok)
	for _, operatedBy := range []string{mcpcontract.OperatedByPerson, mcpcontract.OperatedByAgent} {
		for code, kase := range statusCasesFor(operatedBy) {
			t.Run(operatedBy+"/"+code, func(t *testing.T) {
				t.Parallel()
				requireProblemObeysCatalog(t, statusTool, code, kase, operatedBy)
			})
		}
	}
}

func requireProblemObeysCatalog(t *testing.T, statusTool mcpcontract.Tool, code string, kase statusCase, operatedBy string) {
	t.Helper()
	r := kase.report(t)
	require.Equal(t, operatedBy, r.OperatedBy)
	raw := requireStatusSchema(t, statusTool, r)
	require.NotContains(t, raw, statusCredential, "status never names the credential file")
	require.NotContains(t, raw, "credential-file", "status never names the credential file")
	require.Equal(t, kase.state, r.Guard.State)

	entry, ok := problemEntry(code)
	require.True(t, ok)
	p := findProblem(t, r, code)
	require.Equal(t, entry.Severity, p.Severity)
	require.NotEmpty(t, p.Message)
	got := make([]mcpcontract.StepKind, 0, len(p.NextSteps))
	for _, st := range p.NextSteps {
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
	}
	want, pm, variant := expectedSteps(t, mcpcontract.VariantProblem, code, "", "", entry.Steps, entry.PersonMessage, operatedBy)
	require.Equal(t, want, got, "(actor, action) sequence of %s", code)
	require.Equal(t, pm, p.PersonMessage != "", "personMessage set exactly when the catalog says")
	requireOperatorRules(t, p.NextSteps, p.PersonMessage, variant, code)
	requirePersonMessage(t, p.PersonMessage, nil)
	for i, st := range p.NextSteps {
		requireStepObeysRules(t, st, catalogCase{tool: toolStatus, args: map[string]any{}}, "", fmt.Sprintf("%s step %d", code, i+1))
	}
	require.Equal(t, entry.Severity != mcpcontract.SeverityError, r.Ready, "ready exactly when no ERROR problem")
	for i := 1; i < len(r.Problems); i++ {
		require.LessOrEqual(t, severityRank(r.Problems[i-1].Severity), severityRank(r.Problems[i].Severity), "errors first")
	}
}

func findProblem(t *testing.T, r StatusReport, code string) Problem {
	t.Helper()
	for _, p := range r.Problems {
		if p.Code == code {
			return p
		}
	}
	require.Failf(t, "problem missing", "no %s in %+v", code, r.Problems)
	return Problem{}
}

// requireStatusSchema checks r against the tool's outputSchema and returns
// it as JSON.
func requireStatusSchema(t *testing.T, tool mcpcontract.Tool, r StatusReport) string {
	t.Helper()
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NoError(t, validateSchema(tool.OutputSchema, v), string(raw))
	return string(raw)
}

func TestStatusWhenEverythingIsReady(t *testing.T) {
	t.Parallel()
	r := engineStatus(&fakeProbe{st: guardAt(guard.GuardOK, nil, nil), ledger: 123456, latest: &guard.AgentSetup{SetupID: uuid.MustParse(caseRunID), Kind: guard.SetupAgent}}, 2, nil)(t)
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), toolStatus)
	requireStatusSchema(t, statusTool, r)
	require.True(t, r.Ready)
	require.Empty(t, r.Problems)
	require.NotNil(t, r.Problems, "problems is an empty list, not null")
	require.Equal(t, "bot", r.Agent)
	require.Equal(t, mcpcontract.OperatedByPerson, r.OperatedBy)
	require.Equal(t, EnforcementEngineAndGuard, r.Enforcement)
	require.True(t, r.Engine.Reachable)
	require.Equal(t, guard.GuardOK, r.Guard.State)
	require.Equal(t, PasskeysStatus{Registered: true, Active: ptr(2)}, r.Passkeys)
	require.Equal(t, SetupStatus{State: setupDone, SetupID: caseRunID, Kind: guard.SetupAgent}, r.Setup)
	require.Nil(t, r.Vault, "no vault reporter yet: vault is left out")
	require.Equal(t, &LedgerStatus{Bytes: 123456, ValuesKeptDays: 30, RecordsKeptDays: 365}, r.Ledger)
}

func TestStatusLeavesLedgerOutWhenTheGuardCannotBeRead(t *testing.T) {
	t.Parallel()
	r := engineStatus(&fakeProbe{err: context.DeadlineExceeded, ledger: 123456}, 1, pendingSetup(guard.SetupAgent, statusNow.Add(time.Hour)))(t)
	require.Nil(t, r.Ledger)
	require.False(t, r.Ready)
}

func TestStatusLeavesLedgerOutWhenTheGuardIsMissing(t *testing.T) {
	t.Parallel()
	r := engineStatus(&fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}, ledger: 123456}, 1, pendingSetup(guard.SetupAgent, statusNow.Add(time.Hour)))(t)
	require.Nil(t, r.Ledger)
}

func TestStatusLedgerReadFailureIsNotAProblem(t *testing.T) {
	t.Parallel()
	ok := engineStatus(&fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}, 2, nil)(t)
	r := engineStatus(&fakeProbe{st: guardAt(guard.GuardOK, nil, nil), ledgerErr: errors.New("boom")}, 2, nil)(t)
	require.Nil(t, r.Ledger)
	require.Equal(t, ok.Problems, r.Problems)
	require.True(t, r.Ready)
}

func ptr[T any](v T) *T { return &v }

func TestStatusEnforcementAndOperator(t *testing.T) {
	t.Parallel()
	require.Equal(t, EnforcementGuardOnly, enforcement(mcpcontract.OperatedByAgent, false))
	require.Equal(t, EnforcementGuardOnly, enforcement(mcpcontract.OperatedByPerson, true), "same-user mode")
	require.Equal(t, EnforcementEngineAndGuard, enforcement("", false))
	require.Equal(t, mcpcontract.OperatedByPerson, operatedBy(""))

	// The shim that cannot read the config: PERSON and GUARD_ONLY.
	cmds, err := NewCommands("bot", "", "linux", nil)
	require.NoError(t, err)
	r, err := EngineDownStatus("bot", cmds, nil, "test", statusNow)
	require.NoError(t, err)
	require.Equal(t, mcpcontract.OperatedByPerson, r.OperatedBy)
	require.Equal(t, EnforcementGuardOnly, r.Enforcement)
	require.False(t, r.Engine.Reachable)
	require.False(t, r.Ready)
	require.Equal(t, setupNone, r.Setup.State)
	require.Equal(t, service.StartCommand("linux"), r.Problems[0].NextSteps[0].Command)

	// A same-user config the shim reads: its operator and its foreground engine.
	cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Agents: []config.Agent{{
		Name: "bot", OSUser: "bot", CredentialFile: statusCredential, Setup: pendingSetup(guard.SetupInstall, statusNow.Add(time.Hour)),
	}}}
	r, err = EngineDownStatus("bot", cmds.Foreground(), cfg, "test", statusNow)
	require.NoError(t, err)
	require.Equal(t, mcpcontract.OperatedByAgent, r.OperatedBy)
	require.Equal(t, EnforcementGuardOnly, r.Enforcement)
	require.Equal(t, setupPending, r.Setup.State)
	require.Equal(t, "a1b2 c3d4 e5f6 0718 293a", r.Setup.Fingerprint)
	require.Equal(t, "basalt engine --config /etc/basalt/engine.json", findProblem(t, r, problemEngineUnreachable).NextSteps[0].Command)
	findProblem(t, r, problemSetupNotRun)
}

func TestStatusVaultHook(t *testing.T) {
	t.Parallel()
	d := deps()
	d.Approvals = keys{n: 1}
	d.Vault = fixedVault{VaultStatus{State: "KEY_ERROR"}}
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, &VaultStatus{State: "KEY_ERROR"}, r.Vault)
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), toolStatus)
	requireStatusSchema(t, statusTool, r)
}

type fixedVault struct{ v VaultStatus }

func (f fixedVault) VaultStatus() VaultStatus { return f.v }

func TestSetupStates(t *testing.T) {
	t.Parallel()
	soon, past := statusNow.Add(time.Minute), statusNow.Add(-time.Minute)
	for _, tc := range []struct {
		name     string
		setup    *config.Setup
		recorded bool
		want     string
		code     bool
	}{
		{"none", nil, false, setupNone, false},
		{"pending install", pendingSetup(guard.SetupInstall, soon), false, setupPending, true},
		{"recorded", pendingSetup(guard.SetupInstall, soon), true, setupNone, false},
		{"expired install", pendingSetup(guard.SetupInstall, past), false, setupExpired, true},
		{"expired upgrade is dropped", pendingSetup(guard.SetupUpgrade, past), false, setupNone, false},
		{"pending upgrade", pendingSetup(guard.SetupUpgrade, soon), false, setupPending, true},
	} {
		v := setupFrom(tc.setup, tc.recorded, statusNow)
		require.Equal(t, tc.want, v.status.State, tc.name)
		require.Equal(t, tc.code, v.code != "", tc.name)
		if tc.want == setupExpired {
			require.Empty(t, v.status.Fingerprint, "a fingerprint only while pending")
		}
	}
}

// --- degraded mode ---

// degraded is a service whose probe the test changes between calls.
func degraded(t *testing.T, probe *fakeProbe, setup *config.Setup) (*mcp.Server, []mcp.Tool) {
	t.Helper()
	d := deps()
	d.Probe = probe
	d.Approvals = keys{n: 1}
	d.Setup = setup
	d.Now = func() time.Time { return statusNow }
	tools := Tools(NewService(d))
	return mcp.NewServer(mcp.Info{Name: "basalt"}, tools...), tools
}

func serveCall(t *testing.T, srv *mcp.Server, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, srv.ServeLine(context.Background(), &out, req))
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(out.String()), &resp), out.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &body))
	return body, resp.Result.IsError
}

func steps(t *testing.T, body map[string]any) []mcpcontract.StepKind {
	t.Helper()
	raw, err := json.Marshal(body["nextSteps"])
	require.NoError(t, err)
	var out []mcpcontract.StepKind
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// requireOnlyStatusServed calls every served tool but status on srv and
// checks each is refused UNAVAILABLE reason with the catalog's steps, and
// that status still answers.
func requireOnlyStatusServed(t *testing.T, srv *mcp.Server, tools []mcp.Tool, reason, command, inMessage string) {
	t.Helper()
	entry, ok := catalogOf(t).ErrorEntry(CodeUnavailable, reason, "")
	require.True(t, ok)
	for _, tool := range tools {
		if tool.Name == toolStatus {
			continue
		}
		body, isError := serveCall(t, srv, tool.Name, map[string]any{})
		require.True(t, isError, tool.Name)
		require.Equal(t, CodeUnavailable, body["code"], tool.Name)
		require.Equal(t, reason, body["reason"], tool.Name)
		require.NotEmpty(t, body["errorId"], tool.Name)
		require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
		require.Contains(t, body["personMessage"], inMessage, tool.Name)
		require.Equal(t, command, body["nextSteps"].([]any)[0].(map[string]any)["command"], tool.Name)
	}
	body, isError := serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError, "status is served: %v", body)
	require.Equal(t, false, body["ready"])
}

func TestAnOutdatedGuardServesOnlyStatus(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{st: guardAt(guard.GuardOutdated, []int{guard.LatestVersion()}, nil)}
	srv, tools := degraded(t, probe, nil)
	requireOnlyStatusServed(t, srv, tools, reasonGuardOutdated, "basalt upgrade --agent bot", "basalt upgrade --agent bot")

	// The person upgrades: the next call is served, with no restart.
	probe.st = guardAt(guard.GuardOK, nil, nil)
	body, isError := serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "%v", body)
	require.Nil(t, body["warnings"])
}

func TestAMissingGuardServesOnlyStatus(t *testing.T) {
	t.Parallel()
	srv, tools := degraded(t, &fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}, nil)
	requireOnlyStatusServed(t, srv, tools, reasonGuardMissing, "basalt init --agent bot", "basalt init --agent bot")
}

func TestOnlyNonBreakingMissingIsServedWithTheWarning(t *testing.T) {
	t.Parallel()
	srv, _ := degraded(t, &fakeProbe{st: guardAt(guard.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, nil)
	body, isError := serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "%v", body)
	warnings := body["warnings"].([]any)
	require.Len(t, warnings, 1)
	require.Equal(t, mcp.WarningGuardUpgradeAvailable, warnings[0].(map[string]any)["code"])
}

// errNoRole is the error a pending INSTALL code's agent gets: its role does
// not exist yet, so the database refuses the login.
var errNoRole = &pgconn.PgError{Code: "28P01", Message: "password authentication failed"}

func TestAPendingInstallServesOnlyStatus(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{err: errNoRole, recordedErr: errNoRole}
	srv, tools := degraded(t, probe, pendingSetup(guard.SetupInstall, statusNow.Add(time.Hour)))
	// The person runs the code on their own computer: basalt init
	// --setup-code takes no --agent or --config, and the message names the
	// fingerprint to check, not the code itself.
	requireOnlyStatusServed(t, srv, tools, reasonSetupPending, "basalt init --setup-code "+testSetupCode, testFingerprint)

	body, isError := serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError)
	problems := body["problems"].([]any)
	require.Len(t, problems, 1, "the setup explains the missing role: no database problem besides it")
	require.Equal(t, problemSetupNotRun, problems[0].(map[string]any)["code"])

	// The person ran it and the agent checks status, which reads afresh
	// (held calls may trust a not-recorded answer for a few seconds).
	probe.recorded, probe.recordedErr = true, nil
	probe.err, probe.st = nil, guardAt(guard.GuardOK, nil, nil)
	_, isError = serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError)
	_, isError = serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "a recorded setup is served")
}

// A database that cannot be reached says nothing about the setup code: the
// code may have been used already. Status reports the database, not the
// setup, and the tools answer DATABASE_UNREACHABLE.
func TestAPendingInstallWithTheDatabaseDownReportsTheDatabase(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{err: context.DeadlineExceeded, recordedErr: context.DeadlineExceeded}
	srv, _ := degraded(t, probe, pendingSetup(guard.SetupInstall, statusNow.Add(time.Hour)))

	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, reasonDatabaseUnreachable, body["reason"])

	body, isError = serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError)
	problems := body["problems"].([]any)
	require.Len(t, problems, 1)
	require.Equal(t, problemDatabaseUnreachable, problems[0].(map[string]any)["code"], "no SETUP_NOT_RUN for a code that may be used")
	require.Equal(t, setupPending, body["setup"].(map[string]any)["state"], "the config's code is still shown")
}

func TestStatusRefusesArguments(t *testing.T) {
	t.Parallel()
	srv, _ := degraded(t, &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}, nil)
	body, isError := serveCall(t, srv, toolStatus, map[string]any{"verbose": true})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"])
}

// --- the shim's tools ---

func TestEngineDownToolsAnswerEveryCall(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "/srv/basalt/engine.json", "linux", nil)
	require.NoError(t, err)
	down := EngineDown{Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcp.NewServer(mcp.Info{Name: "basalt"}, down.Tools()...)

	served := make([]string, 0, len(down.Tools()))
	for _, tool := range down.Tools() {
		served = append(served, tool.Name)
	}
	sort.Strings(served)
	require.NoError(t, mcpcontract.CheckServed(mcpcontract.MustLoad(), served), "the shim lists exactly the IMPLEMENTED contracts")

	entry, ok := catalogOf(t).ErrorEntry(CodeUnavailable, reasonEngineUnreachable, "query")
	require.True(t, ok)
	for _, tool := range served {
		if tool == toolStatus {
			continue
		}
		body, isError := serveCall(t, srv, tool, map[string]any{})
		require.True(t, isError, tool)
		require.Equal(t, CodeUnavailable, body["code"], tool)
		require.Equal(t, reasonEngineUnreachable, body["reason"], tool)
		require.NotEmpty(t, body["errorId"], tool)
		require.NotEmpty(t, body["personMessage"], tool)
		require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool)
		require.Equal(t, service.StartCommand("linux"), body["nextSteps"].([]any)[0].(map[string]any)["command"], tool)
	}
	body, isError := serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, false, body["engine"].(map[string]any)["reachable"])
	require.Equal(t, guard.GuardUnknown, body["guard"].(map[string]any)["state"])
	require.Equal(t, mcpcontract.OperatedByPerson, body["operatedBy"])

	body, isError = serveCall(t, srv, toolStatus, map[string]any{"x": 1})
	require.True(t, isError)
	require.Equal(t, CodeInvalidArgument, body["code"])
	require.NotEmpty(t, body["nextSteps"])
}

// The shim reads operatedBy from the config: on an agent-operated engine the
// agent starts the engine itself, once, then repeats its call; the shim
// that cannot read the config keeps the person's steps (the default above).
func TestEngineDownOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", nil)
	require.NoError(t, err)
	cfg := &config.Config{
		SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Mode: config.ModeService,
		Agents: []config.Agent{{Name: "bot", OSUser: "bot", CredentialFile: statusCredential}},
	}
	down := EngineDown{Name: "bot", Commands: cmds, Config: cfg, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcp.NewServer(mcp.Info{Name: "basalt"}, down.Tools()...)

	v, ok := catalogOf(t).AgentOperatedEntry(mcpcontract.VariantError, CodeUnavailable, reasonEngineUnreachable, "")
	require.True(t, ok)
	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, v.Steps, steps(t, body))
	require.Nil(t, body["personMessage"], "the agent starts it: nothing for the person")
	first := body["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, service.StartCommand("linux"), first["command"])
	second := body["nextSteps"].([]any)[1].(map[string]any)
	require.Equal(t, "query", second["tool"])
	require.Equal(t, true, second["repeatCall"])

	body, isError = serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, mcpcontract.OperatedByAgent, body["operatedBy"])
	p := body["problems"].([]any)[0].(map[string]any)
	require.Equal(t, mcpcontract.ActorAgent, p["nextSteps"].([]any)[0].(map[string]any)["actor"])
}

// TestStatusProblemsStayWithinTheLimitWithALongConfigPath: a 252-character
// config path and the flags init saves must not make the status call fail
// on a personMessage over 500 characters; the commands then stand in the
// PERSON steps only.
func TestStatusProblemsStayWithinTheLimitWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	saved := []string{
		"--agent=bot", "--write=public.leads,public.lead_notes", "--read=public.owners", "--prefix=acme",
		"--passkey-origin=https://portal.basaltvault.app", "--statement-timeout=30s", "--os-user=deploy",
	}
	ok := guardAt(guard.GuardOK, nil, nil)
	soon := statusNow.Add(time.Hour)
	reports := map[string]func(t *testing.T) StatusReport{
		"credential rejected":  operatedStatusWith(&fakeProbe{err: &pgconn.PgError{Code: "28P01", Message: "password authentication failed"}}, 1, nil, "", long, saved),
		"database unreachable": operatedStatusWith(&fakeProbe{err: fmt.Errorf("dial: %w", context.DeadlineExceeded)}, 1, nil, "", long, saved),
		"guard missing":        operatedStatusWith(&fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}, 1, nil, "", long, saved),
		"guard outdated":       operatedStatusWith(&fakeProbe{st: guardAt(guard.GuardOutdated, []int{guard.LatestVersion()}, nil)}, 1, nil, "", long, saved),
		"upgrade available":    operatedStatusWith(&fakeProbe{st: guardAt(guard.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, 1, nil, "", long, saved),
		"no passkey":           operatedStatusWith(&fakeProbe{st: ok}, 0, nil, "", long, saved),
		"setup not run":        operatedStatusWith(&fakeProbe{st: guard.Status{State: guard.GuardMissing, Build: guard.LatestVersion()}}, 0, pendingSetup(guard.SetupInstall, soon), "", long, saved),
		"setup change pending": operatedStatusWith(&fakeProbe{st: ok}, 1, pendingSetup(guard.SetupAgent, soon), "", long, saved),
	}
	for name, report := range reports {
		r := report(t)
		require.NotEmpty(t, r.Problems, name)
		for _, p := range r.Problems {
			require.NoError(t, CheckPersonMessage(p.PersonMessage), "%s: %s: %s", name, p.Code, p.PersonMessage)
		}
	}
}

// lockTroubleStatus is the status of an engine whose setup is recorded but
// whose config lock file a root process left unopenable.
func lockTroubleStatus(t *testing.T, operatedBy string) StatusReport {
	t.Helper()
	d := deps()
	d.OperatedBy = operatedBy
	d.Probe = &fakeProbe{st: guardAt(guard.GuardOK, nil, nil), recorded: true}
	d.Approvals = keys{n: 1}
	d.Setup = pendingSetup(guard.SetupAgent, statusNow.Add(time.Hour))
	d.Now = func() time.Time { return statusNow }
	d.Finisher = &fakeFinisher{finishErr: &config.LockUnusableError{Path: "/etc/basalt/engine.json.lock", Err: os.ErrPermission}}
	cmds, err := NewCommands("bot", "", "linux", []string{"--agent=bot", "--write=public.leads"})
	require.NoError(t, err)
	d.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}
