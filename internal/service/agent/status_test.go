package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// This file is the contract test of the status tool (CONTRACT.md, MCP tools,
// status) and of degraded mode: every problem of the catalog has a case,
// every case's report validates against status.json's outputSchema, its
// problem obeys the catalog, and nothing in it names the credential file.

// statusCredential is a credential file path no status output may hold.
const statusCredential = "/etc/basalt/agents/bot.url"

// fakeProbe is a Probe with a fixed answer.
type fakeProbe struct {
	st       guardmodel.Status
	err      error
	recorded bool
	// recordedErr fails SetupRecorded.
	recordedErr error
	latest      *guardmodel.AgentSetup
	// ledger is LedgerBytes's answer; ledgerErr fails it.
	ledger    int64
	ledgerErr error
	// reinstalls is Reinstalls's answer.
	reinstalls guard.Reinstalls
}

func (p *fakeProbe) LedgerBytes(context.Context) (int64, error) { return p.ledger, p.ledgerErr }

func (p *fakeProbe) ReinstallNotice(_ context.Context, limit int) (string, bool, error) {
	msg, ok := ledger.ReinstallPersonMessage(p.reinstalls, limit)
	return msg, ok, nil
}

func (p *fakeProbe) GuardStatus(context.Context) (guardmodel.Status, error) { return p.st, p.err }

func (p *fakeProbe) SetupRecorded(context.Context, uuid.UUID) (bool, error) {
	return p.recorded, p.recordedErr
}

func (p *fakeProbe) LatestSetup(context.Context) (guardmodel.AgentSetup, bool, error) {
	if p.latest == nil {
		return guardmodel.AgentSetup{}, false, nil
	}
	return *p.latest, true, nil
}

// keys answers Passkeys with n passkeys.
type keys struct {
	approvalStore
	n int
}

func (k keys) Passkeys(context.Context) ([]passkey.Credential, error) {
	return testCredentials(k.n), nil
}

// testKeys are eight fixed-for-the-run P-256 credentials with ids 1..8,
// registered on the default local pages.
var testKeys = sync.OnceValue(func() []passkey.Credential {
	out := make([]passkey.Credential, 8)
	for i := range out {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		// On the default local pages, where the agent's links open unless a
		// test sets another pages base.
		out[i] = passkey.Credential{ID: []byte{byte(i + 1)}, PublicKey: &k.PublicKey, Relying: passkey.Relying{RPID: "localhost", Origin: links.DefaultLocal}}
	}
	return out
})

// testCredentials are the first n of them, with distinct keys and ids.
func testCredentials(n int) []passkey.Credential { return testKeys()[:n] }

func guardAt(state string, missingBreaking, missingNonBreaking []int) guardmodel.Status {
	b := guard.LatestVersion()
	installed := b
	if state == guardmodel.GuardNewer {
		installed = b + 1
	}
	return guardmodel.Status{State: state, Installed: installed, Build: b, MissingBreaking: missingBreaking, MissingNonBreaking: missingNonBreaking}
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
	return operatedStatusWith(probe, passkeys, setup, operatedBy, "")
}

// operatedStatusWith is operatedStatus with the engine config at configPath
// and the flags init saved.
func operatedStatusWith(probe *fakeProbe, passkeys int, setup *config.Setup, operatedBy, configPath string) func(t *testing.T) StatusReport {
	return func(t *testing.T) StatusReport {
		t.Helper()
		d := deps()
		d.Status.OperatedBy = operatedBy
		d.Status.Probe = probe
		setApprovals(&d, keys{n: passkeys})
		d.Status.Setup = setup
		d.Core.Now = func() time.Time { return statusNow }
		// The credential file is at init's default, so no saved flag names it
		// (a saved --credential-file stays in init commands, AE-15).
		cmds, err := NewCommands("bot", configPath, "linux", testManager())
		require.NoError(t, err)
		d.Core.Commands = cmds
		r, err := NewService(d).Status(context.Background())
		require.NoError(t, err)
		return r
	}
}

func statusCases() map[string]statusCase { return statusCasesFor("") }

// statusCasesFor are the status cases on an engine whose operatedBy is
// operatedBy.
func statusCasesFor(operatedBy string) map[string]statusCase {
	ok := guardAt(guardmodel.GuardOK, nil, nil)
	soon, past := statusNow.Add(time.Hour), statusNow.Add(-time.Hour)
	engineStatus := func(probe *fakeProbe, passkeys int, setup *config.Setup) func(t *testing.T) StatusReport {
		return operatedStatus(probe, passkeys, setup, operatedBy)
	}
	cases := map[string]statusCase{
		problemEngineUnreachable: {state: guardmodel.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			cmds, err := NewCommands("bot", "", "linux", testManager())
			require.NoError(t, err)
			cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: operatedBy, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
			r, err := EngineDownStatus(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow)
			require.NoError(t, err)
			return r
		}},
		problemEngineStartFailed: {state: guardmodel.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			cmds, err := NewCommands("bot", "", "linux", testManager())
			require.NoError(t, err)
			cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: operatedBy, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
			r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow, "basalt mcp could not start the engine: the basalt binary /x/basalt is gone. Its log is /s/engine.log.", "")
			require.NoError(t, err)
			return r
		}},
		problemEngineGaveUp: {state: guardmodel.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			cmds, err := NewCommands("bot", "", "linux", testManager())
			require.NoError(t, err)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, lastStopFile), []byte(`{"reason":"the engine crashed 5 times within 10s; last: exit status 1","at":"2026-11-20T01:02:03Z"}`), 0o600))
			cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, OperatedBy: operatedBy, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
			r, err := EngineDownStatus(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow)
			require.NoError(t, err)
			return r
		}},
		problemDatabaseUnreachable: {state: guardmodel.GuardUnknown, report: engineStatus(&fakeProbe{err: fmt.Errorf("dial %s: %w", statusCredential, context.DeadlineExceeded)}, 1, nil)},
		problemTooManyConnections: {state: guardmodel.GuardUnknown, report: engineStatus(&fakeProbe{err: store.MapError(&pgconn.PgError{
			Code:    "53300",
			Message: `too many connections for role "basalt_agent_bot"`,
		})}, 1, nil)},
		problemCredentialRejected: {state: guardmodel.GuardUnknown, report: engineStatus(&fakeProbe{err: store.MapError(&pgconn.PgError{
			Code:    "28P01",
			Message: "password authentication failed (" + statusCredential + ")",
		})}, 1, nil)},
		problemGuardMissing:       {state: guardmodel.GuardMissing, report: engineStatus(&fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}}, 1, nil)},
		problemGuardOutdated:      {state: guardmodel.GuardOutdated, report: engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardOutdated, []int{guard.LatestVersion()}, nil)}, 1, nil)},
		problemUpgradeAvailable:   {state: guardmodel.GuardUpgradeAvailable, report: engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, 1, nil)},
		problemNoPasskey:          {state: guardmodel.GuardOK, report: engineStatus(&fakeProbe{st: ok}, 0, nil)},
		problemSetupNotRun:        {state: guardmodel.GuardMissing, report: engineStatus(&fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}}, 0, pendingSetup(guardmodel.SetupInstall, soon))},
		problemSetupExpired:       {state: guardmodel.GuardUnknown, report: engineStatus(&fakeProbe{err: store.MapError(&pgconn.PgError{Code: "28000", Message: "role does not exist"})}, 0, pendingSetup(guardmodel.SetupInstall, past))},
		problemSetupChangePending: {state: guardmodel.GuardOK, report: engineStatus(&fakeProbe{st: ok}, 1, pendingSetup(guardmodel.SetupAgent, soon))},
		problemLockFileUnusable: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return lockTroubleStatus(t, operatedBy)
		}},
		problemPortalMismatch: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return portalStatus(t, operatedBy, fakePortal{ok: true, f: PortalFinding{CheckedAt: statusNow, Mismatch: true, Summary: "2 DIFFERS, 1 MISSING"}})
		}},
		problemDevLocalPages: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return devLocalStatus(t, operatedBy)
		}},
		problemEngineRevoked: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return engineRecordStatusOf(t, operatedBy, recordOf(true))
		}},
		problemLedgerReinstalled: {state: guardmodel.GuardOK, report: engineStatus(&fakeProbe{st: ok, reinstalls: sampleReinstalls()}, 1, nil)},
		ProblemPluginUnavailable: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", false, samplePluginProblem(ProblemPluginUnavailable))
		}},
		ProblemPluginNotTrusted: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", false, samplePluginProblem(ProblemPluginNotTrusted))
		}},
		// Plugin approvals are same-user mode: a foreground engine.
		ProblemPluginAwaitingApproval: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", true, samplePluginProblem(ProblemPluginAwaitingApproval))
		}},
		ProblemPluginApprovalExpired: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", true, samplePluginProblem(ProblemPluginApprovalExpired))
		}},
		ProblemPluginApprovalMismatch: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", true, samplePluginProblem(ProblemPluginApprovalMismatch))
		}},
		ProblemPluginConfigInvalid: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", true, fakePlugins{"bot": {{Code: ProblemPluginConfigInvalid, Message: "engine.json changed and the engine cannot read its plugins"}}})
		}},
		ProblemPluginNoticesDropped: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return pluginStatus(t, operatedBy, "", true, samplePluginProblem(ProblemPluginNoticesDropped))
		}},
	}
	maps.Copy(cases, trustStatusCases(operatedBy))
	maps.Copy(cases, connectOnlyStatusCases(operatedBy))
	return cases
}

// sampleReinstalls is one reinstall reported by two agents.
func sampleReinstalls() guard.Reinstalls {
	installed := statusNow.Add(-time.Hour)
	hash := make([]byte, 32)
	return guard.Reinstalls{List: []guard.Reinstall{{
		Install: uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2b"), InstalledAt: &installed, InstalledBy: "postgres",
		Reports: []guard.ReinstallReport{
			{Agent: "basalt_agent_bot", At: statusNow, PinnedSeq: 42, PinnedHash: hash},
			{Agent: "basalt_agent_other", At: statusNow, PinnedSeq: 40, PinnedHash: hash},
		},
	}}}
}

// LEDGER_REINSTALLED carries the newest reinstall's first notice line and
// points to basalt log; the tools keep working. No reinstall, no problem.
func TestStatusLedgerReinstalled(t *testing.T) {
	t.Parallel()
	ok := guardAt(guardmodel.GuardOK, nil, nil)
	r := engineStatus(&fakeProbe{st: ok, reinstalls: sampleReinstalls()}, 1, nil)(t)
	p := findProblem(t, r, problemLedgerReinstalled)
	require.True(t, r.Ready)
	require.Equal(t, mcpcontract.SeverityWarning, p.Severity)
	require.Equal(t, ledger.ReinstallNotice(sampleReinstalls().List[0])[0]+"\nOlder reports stay in the ledger's install records.", p.PersonMessage)
	require.NotContains(t, p.PersonMessage, "basalt_agent_other")

	r = engineStatus(&fakeProbe{st: ok}, 1, nil)(t)
	for _, p := range r.Problems {
		require.NotEqual(t, problemLedgerReinstalled, p.Code)
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
	statusTool, ok := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)
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

	entry, ok := guidance.ProblemEntry(code)
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
	requireOperatorRules(t, p.NextSteps, p.PersonMessage, variant, operatedBy, code)
	requirePersonMessage(t, p.PersonMessage, nil)
	for i, st := range p.NextSteps {
		where := fmt.Sprintf("%s step %d", code, i+1)
		if code == ProblemPluginAwaitingApproval && st.Action == toolresult.ActionOpenLink {
			// No url: the link the agent handed over when the approval was
			// opened, which the engine never had (CONTRACT.md, Next steps
			// per code).
			require.Empty(t, st.URL, where)
			require.Empty(t, st.Command, where)
			require.NotEmpty(t, st.Text, where)
			continue
		}
		requireStepObeysRules(t, st, catalogCase{tool: guidance.ToolStatus, args: map[string]any{}}, where)
	}
	require.Equal(t, entry.Severity != mcpcontract.SeverityError, r.Ready, "ready exactly when no ERROR problem")
	for i := 1; i < len(r.Problems); i++ {
		require.LessOrEqual(t, guidance.SeverityRank(r.Problems[i-1].Severity), guidance.SeverityRank(r.Problems[i].Severity), "errors first")
	}
}

func findProblem(t *testing.T, r StatusReport, code string) guidance.Problem {
	t.Helper()
	for _, p := range r.Problems {
		if p.Code == code {
			return p
		}
	}
	require.Failf(t, "problem missing", "no %s in %+v", code, r.Problems)
	return guidance.Problem{}
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
	r := engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), ledger: 123456, latest: &guardmodel.AgentSetup{SetupID: uuid.MustParse(caseRunID), Kind: guardmodel.SetupAgent}}, 2, nil)(t)
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)
	requireStatusSchema(t, statusTool, r)
	require.True(t, r.Ready)
	require.Empty(t, r.Problems)
	require.NotNil(t, r.Problems, "problems is an empty list, not null")
	require.Equal(t, "bot", r.Agent)
	require.Equal(t, mcpcontract.OperatedByPerson, r.OperatedBy)
	require.Equal(t, EnforcementEngineAndGuard, r.Enforcement)
	require.True(t, r.Engine.Reachable)
	require.Equal(t, guardmodel.GuardOK, r.Guard.State)
	require.True(t, r.Passkeys.Registered)
	require.Equal(t, ptr(2), r.Passkeys.Active)
	require.Equal(t, SetupStatus{State: setupDone, SetupID: caseRunID, Kind: guardmodel.SetupAgent}, r.Setup)
	require.Nil(t, r.Vault, "no vault reporter yet: vault is left out")
	require.Equal(t, &LedgerStatus{Bytes: 123456, ValuesKeptDays: 30, RecordsKeptDays: 365}, r.Ledger)
}

func TestStatusLeavesLedgerOutWhenTheGuardCannotBeRead(t *testing.T) {
	t.Parallel()
	r := engineStatus(&fakeProbe{err: context.DeadlineExceeded, ledger: 123456}, 1, pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour)))(t)
	require.Nil(t, r.Ledger)
	require.False(t, r.Ready)
}

func TestStatusLeavesLedgerOutWhenTheGuardIsMissing(t *testing.T) {
	t.Parallel()
	r := engineStatus(&fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}, ledger: 123456}, 1, pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour)))(t)
	require.Nil(t, r.Ledger)
}

func TestStatusLedgerReadFailureIsNotAProblem(t *testing.T) {
	t.Parallel()
	ok := engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}, 2, nil)(t)
	r := engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), ledgerErr: errors.New("boom")}, 2, nil)(t)
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
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	r, err := EngineDownStatus(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow)
	require.NoError(t, err)
	require.Equal(t, mcpcontract.OperatedByPerson, r.OperatedBy)
	require.Equal(t, EnforcementGuardOnly, r.Enforcement)
	require.False(t, r.Engine.Reachable)
	require.False(t, r.Ready)
	require.Equal(t, setupNone, r.Setup.State)
	require.Equal(t, osservice.StartCommand("linux"), r.Problems[0].NextSteps[0].Command)

	// A same-user config the shim reads: its operator and its foreground engine.
	cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Agents: []config.Agent{{
		Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential), Setup: pendingSetup(guardmodel.SetupInstall, statusNow.Add(time.Hour)),
	}}}
	r, err = EngineDownStatus(testEngineHost(), "bot", cmds.Foreground(), cfg, nil, "test", statusNow)
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
	setApprovals(&d, keys{n: 1})
	d.Status.Vault = fixedVault{VaultStatus{State: "KEY_ERROR"}}
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, &VaultStatus{State: "KEY_ERROR"}, r.Vault)
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)
	requireStatusSchema(t, statusTool, r)
}

type fixedVault struct{ v VaultStatus }

func (f fixedVault) VaultStatus() VaultStatus { return f.v }

func TestSetupStates(t *testing.T) {
	t.Parallel()
	soon, past, afterHold := statusNow.Add(time.Minute), statusNow.Add(-time.Minute), statusNow.Add(-31*time.Minute)
	awaiting := connectOnlySetup(soon)
	hold := connectOnlySetup(past)
	ended := connectOnlySetup(afterHold)
	confirmed := connectOnlySetup(past)
	confirmed.AwaitingAddress = false
	for _, tc := range []struct {
		name     string
		setup    *config.Setup
		recorded bool
		want     string
		code     bool
	}{
		{"none", nil, false, setupNone, false},
		{"pending install", pendingSetup(guardmodel.SetupInstall, soon), false, setupPending, true},
		{"recorded", pendingSetup(guardmodel.SetupInstall, soon), true, setupNone, false},
		{"expired install", pendingSetup(guardmodel.SetupInstall, past), false, setupExpired, false},
		{"expired upgrade is dropped", pendingSetup(guardmodel.SetupUpgrade, past), false, setupNone, false},
		{"pending upgrade", pendingSetup(guardmodel.SetupUpgrade, soon), false, setupPending, true},
		{"pending connect-only", &awaiting, false, setupPending, true},
		{"connect-only hold after expiry", &hold, false, setupPending, false},
		{"connect-only after the collect window", &ended, false, setupExpired, false},
		{"confirmed connect-only after expiry", &confirmed, false, setupPending, false},
	} {
		v := setupFrom(tc.setup, tc.recorded, statusNow)
		require.Equal(t, tc.want, v.status.State, tc.name)
		require.Equal(t, tc.code, v.code != "", tc.name)
		if !tc.code {
			require.Empty(t, v.fingerprint, tc.name)
			require.Empty(t, v.status.Fingerprint, tc.name)
		}
		if tc.want == setupExpired {
			require.Empty(t, v.status.Fingerprint, "a fingerprint only while pending")
		}
	}
}

// --- degraded mode ---

// degraded is a service whose probe the test changes between calls.
func degraded(t *testing.T, probe *fakeProbe, setup *config.Setup) (*mcpserver.Server, []mcpserver.Tool) {
	t.Helper()
	d := deps()
	d.Status.Probe = probe
	setApprovals(&d, keys{n: 1})
	d.Status.Setup = setup
	d.Core.Now = func() time.Time { return statusNow }
	tools := Tools(NewService(d))
	return mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(tools, WithMeta)...), mcpserver.ToolsFrom(tools, WithMeta)
}

func serveCall(t *testing.T, srv *mcpserver.Server, tool string, args map[string]any) (map[string]any, bool) {
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
func requireOnlyStatusServed(t *testing.T, srv *mcpserver.Server, tools []mcpserver.Tool, reason, inMessage string) {
	t.Helper()
	entry, ok := catalogOf(t).ErrorEntry(guidance.CodeUnavailable, reason, "")
	require.True(t, ok)
	for _, tool := range tools {
		if tool.Name == guidance.ToolStatus {
			continue
		}
		if tool.Name == toolConfirmDatabase {
			// No connect-only database waits here: INVALID_ARGUMENT, never
			// admitted further.
			body, isError := serveCall(t, srv, tool.Name, map[string]any{})
			require.True(t, isError)
			require.Equal(t, guidance.CodeInvalidArgument, body["code"])
			continue
		}
		body, isError := serveCall(t, srv, tool.Name, map[string]any{})
		require.True(t, isError, tool.Name)
		require.Equal(t, guidance.CodeUnavailable, body["code"], tool.Name)
		require.Equal(t, reason, body["reason"], tool.Name)
		require.NotEmpty(t, body["errorId"], tool.Name)
		require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
		require.Contains(t, body["personMessage"], inMessage, tool.Name)
		require.Equal(t, "basalt init --agent bot", body["nextSteps"].([]any)[0].(map[string]any)["command"], tool.Name)
	}
	body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError, "status is served: %v", body)
	require.Equal(t, false, body["ready"])
}

func TestAnOutdatedGuardServesOnlyStatus(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{st: guardAt(guardmodel.GuardOutdated, []int{guard.LatestVersion()}, nil)}
	srv, tools := degraded(t, probe, nil)
	requireOnlyStatusServed(t, srv, tools, guidance.ReasonGuardOutdated, "The agent gives you a link")

	// The person upgrades: the next call is served, with no restart.
	probe.st = guardAt(guardmodel.GuardOK, nil, nil)
	body, isError := serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "%v", body)
	require.Nil(t, body["warnings"])
}

func TestAMissingGuardServesOnlyStatus(t *testing.T) {
	t.Parallel()
	srv, tools := degraded(t, &fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}}, nil)
	requireOnlyStatusServed(t, srv, tools, guidance.ReasonGuardMissing, "The agent gives you a link")
}

func TestOnlyNonBreakingMissingIsServedWithTheWarning(t *testing.T) {
	t.Parallel()
	srv, _ := degraded(t, &fakeProbe{st: guardAt(guardmodel.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, nil)
	body, isError := serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "%v", body)
	warnings := body["warnings"].([]any)
	require.Len(t, warnings, 1)
	require.Equal(t, toolresult.WarningGuardUpgradeAvailable, warnings[0].(map[string]any)["code"])
}

// errNoRole is the error a pending INSTALL code's agent gets: its role does
// not exist yet, so the database refuses the login.
var errNoRole = store.MapError(&pgconn.PgError{Code: "28P01", Message: "password authentication failed"})

func TestAPendingInstallServesOnlyStatus(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{err: errNoRole, recordedErr: errNoRole}
	srv, tools := degraded(t, probe, pendingSetup(guardmodel.SetupInstall, statusNow.Add(time.Hour)))
	// The person runs the code on their own computer: basalt init
	// --setup-code takes no --agent or --config, and the message names the
	// fingerprint to check, not the code itself.
	requireOnlyStatusServed(t, srv, tools, guidance.ReasonSetupPending, testFingerprint)

	body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	problems := body["problems"].([]any)
	require.Len(t, problems, 1, "the setup explains the missing role: no database problem besides it")
	require.Equal(t, problemSetupNotRun, problems[0].(map[string]any)["code"])

	// The person ran it and the agent checks status, which reads afresh
	// (held calls may trust a not-recorded answer for a few seconds).
	probe.recorded, probe.recordedErr = true, nil
	probe.err, probe.st = nil, guardAt(guardmodel.GuardOK, nil, nil)
	_, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{})
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
	srv, _ := degraded(t, probe, pendingSetup(guardmodel.SetupInstall, statusNow.Add(time.Hour)))

	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, guidance.ReasonDatabaseUnreachable, body["reason"])

	body, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	problems := body["problems"].([]any)
	require.Len(t, problems, 1)
	require.Equal(t, problemDatabaseUnreachable, problems[0].(map[string]any)["code"], "no SETUP_NOT_RUN for a code that may be used")
	require.Equal(t, setupPending, body["setup"].(map[string]any)["state"], "the config's code is still shown")
}

func TestStatusRefusesArguments(t *testing.T) {
	t.Parallel()
	srv, _ := degraded(t, &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}, nil)
	body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{"verbose": true})
	require.True(t, isError)
	require.Equal(t, guidance.CodeInvalidArgument, body["code"])
}

// --- the shim's tools ---

func TestEngineDownToolsAnswerEveryCall(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "/srv/basalt/engine.json", "linux", testManager())
	require.NoError(t, err)
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(down.Tools(), WithMeta)...)

	served := make([]string, 0, len(down.Tools()))
	for _, tool := range down.Tools() {
		served = append(served, tool.Name)
	}
	sort.Strings(served)
	require.NoError(t, mcpcontract.CheckServed(mcpcontract.MustLoad(), served), "the shim lists exactly the IMPLEMENTED contracts")

	entry, ok := catalogOf(t).ErrorEntry(guidance.CodeUnavailable, guidance.ReasonEngineUnreachable, "query")
	require.True(t, ok)
	for _, tool := range served {
		if tool == guidance.ToolStatus {
			continue
		}
		body, isError := serveCall(t, srv, tool, map[string]any{})
		require.True(t, isError, tool)
		require.Equal(t, guidance.CodeUnavailable, body["code"], tool)
		require.Equal(t, guidance.ReasonEngineUnreachable, body["reason"], tool)
		require.NotEmpty(t, body["errorId"], tool)
		require.NotEmpty(t, body["personMessage"], tool)
		require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool)
		require.Equal(t, osservice.StartCommand("linux"), body["nextSteps"].([]any)[0].(map[string]any)["command"], tool)
	}
	body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, false, body["engine"].(map[string]any)["reachable"])
	require.Equal(t, guardmodel.GuardUnknown, body["guard"].(map[string]any)["state"])
	require.Equal(t, mcpcontract.OperatedByPerson, body["operatedBy"])

	body, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{"x": 1})
	require.True(t, isError)
	require.Equal(t, guidance.CodeInvalidArgument, body["code"])
	require.NotEmpty(t, body["nextSteps"])
}

// The shim reads operatedBy from the config: on an agent-operated engine the
// agent starts the engine itself, once, then repeats its call; the shim
// that cannot read the config keeps the person's steps (the default above).
func TestEngineDownOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	cfg := &config.Config{
		SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Mode: config.ModeService,
		Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}},
	}
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Config: cfg, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(down.Tools(), WithMeta)...)

	v, ok := catalogOf(t).AgentOperatedEntry(mcpcontract.VariantError, guidance.CodeUnavailable, guidance.ReasonEngineUnreachable, "")
	require.True(t, ok)
	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, v.Steps, steps(t, body))
	require.Nil(t, body["personMessage"], "the agent starts it: nothing for the person")
	first := body["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, osservice.StartCommand("linux"), first["command"])
	second := body["nextSteps"].([]any)[1].(map[string]any)
	require.Equal(t, "query", second["tool"])
	require.Equal(t, true, second["repeatCall"])

	body, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, mcpcontract.OperatedByAgent, body["operatedBy"])
	p := body["problems"].([]any)[0].(map[string]any)
	require.Equal(t, mcpcontract.ActorAgent, p["nextSteps"].([]any)[0].(map[string]any)["actor"])
}

// TestStatusProblemsStayWithinTheLimitWithALongConfigPath: a 252-character
// config path must not make the status call fail on a personMessage over
// 500 characters, and no message names it: steps never carry --config.
func TestStatusProblemsStayWithinTheLimitWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	ok := guardAt(guardmodel.GuardOK, nil, nil)
	soon := statusNow.Add(time.Hour)
	reports := map[string]func(t *testing.T) StatusReport{
		"credential rejected":  operatedStatusWith(&fakeProbe{err: store.MapError(&pgconn.PgError{Code: "28P01", Message: "password authentication failed"})}, 1, nil, "", long),
		"database unreachable": operatedStatusWith(&fakeProbe{err: fmt.Errorf("dial: %w", context.DeadlineExceeded)}, 1, nil, "", long),
		"guard missing":        operatedStatusWith(&fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}}, 1, nil, "", long),
		"guard outdated":       operatedStatusWith(&fakeProbe{st: guardAt(guardmodel.GuardOutdated, []int{guard.LatestVersion()}, nil)}, 1, nil, "", long),
		"upgrade available":    operatedStatusWith(&fakeProbe{st: guardAt(guardmodel.GuardUpgradeAvailable, nil, []int{guard.LatestVersion()})}, 1, nil, "", long),
		"no passkey":           operatedStatusWith(&fakeProbe{st: ok}, 0, nil, "", long),
		"setup not run":        operatedStatusWith(&fakeProbe{st: guardmodel.Status{State: guardmodel.GuardMissing, Build: guard.LatestVersion()}}, 0, pendingSetup(guardmodel.SetupInstall, soon), "", long),
		"setup change pending": operatedStatusWith(&fakeProbe{st: ok}, 1, pendingSetup(guardmodel.SetupAgent, soon), "", long),
	}
	for name, report := range reports {
		r := report(t)
		require.NotEmpty(t, r.Problems, name)
		for _, p := range r.Problems {
			require.NoError(t, guidance.CheckPersonMessage(p.PersonMessage), "%s: %s: %s", name, p.Code, p.PersonMessage)
			require.NotContains(t, p.PersonMessage, long, "%s: %s", name, p.Code)
		}
	}
}

// lockTroubleStatus is the status of an engine whose setup is recorded but
// whose config lock file a root process left unopenable.
func lockTroubleStatus(t *testing.T, operatedBy string) StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recorded: true}
	setApprovals(&d, keys{n: 1})
	d.Status.Setup = pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour))
	d.Core.Now = func() time.Time { return statusNow }
	d.Status.Finisher = &fakeFinisher{finishErr: &config.LockUnusableError{Path: "/etc/basalt/engine.json.lock", Err: os.ErrPermission}}
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

// engineID is the id the test engine reports.
const testEngineID = "AAAAAAAAAAAAAAAAAAAAAA"

func recordOf(revoked bool) func(context.Context, string) (*EngineRecord, error) {
	return func(_ context.Context, _ string) (*EngineRecord, error) {
		e := &EngineRecord{RecordedAt: statusNow.Add(-48 * time.Hour)}
		if revoked {
			at := statusNow.Add(-time.Hour)
			e.RevokedAt = &at
		}
		return e, nil
	}
}

// engineRecordStatusOf is the status of a ready agent on an engine with a
// Vault reporter whose record is read by read.
func engineRecordStatusOf(t *testing.T, operatedBy string, read EngineRecordReader) StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	d.Status.Vault = fixedVault{VaultStatus{State: "OFF", EngineID: testEngineID}}
	d.Status.EngineRecord = read
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

func TestStatusEngineRecord(t *testing.T) {
	t.Parallel()
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)
	recorded := statusNow.Add(-48 * time.Hour).Format(time.RFC3339)
	revokedAt := statusNow.Add(-time.Hour).Format(time.RFC3339)
	for name, tc := range map[string]struct {
		read EngineRecordReader
		want EngineRecordStatus
		code string
	}{
		"recorded":     {read: recordOf(false), want: EngineRecordStatus{State: engineRecorded, RecordedAt: recorded}},
		"revoked":      {read: recordOf(true), want: EngineRecordStatus{State: engineRevoked, RecordedAt: recorded, RevokedAt: revokedAt}, code: problemEngineRevoked},
		"not recorded": {read: notRecorded, want: EngineRecordStatus{State: engineNotRecorded}},
		"unreadable (a guard before version 33)": {read: func(context.Context, string) (*EngineRecord, error) {
			return nil, errors.New("relation does not exist")
		}, want: EngineRecordStatus{State: engineUnknown}},
		"no reader": {want: EngineRecordStatus{State: engineUnknown}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := engineRecordStatusOf(t, "", tc.read)
			require.Equal(t, &tc.want, r.EngineRecord)
			requireStatusSchema(t, statusTool, r)
			var codes []string
			for _, p := range r.Problems {
				codes = append(codes, p.Code)
			}
			if tc.code == "" {
				require.Empty(t, codes)
				return
			}
			require.Equal(t, []string{tc.code}, codes)
			require.True(t, r.Ready, "a warning")
		})
	}

	t.Run("the key file is refused", func(t *testing.T) {
		t.Parallel()
		d := deps()
		setApprovals(&d, keys{n: 1})
		d.Status.Vault = fixedVault{VaultStatus{State: "KEY_ERROR"}}
		d.Status.EngineRecord = recordOf(true)
		r, err := NewService(d).Status(context.Background())
		require.NoError(t, err)
		require.Equal(t, &EngineRecordStatus{State: engineUnknown}, r.EngineRecord)
		require.Empty(t, r.Problems)
	})
	t.Run("no vault reporter: left out", func(t *testing.T) {
		t.Parallel()
		d := deps()
		setApprovals(&d, keys{n: 1})
		r, err := NewService(d).Status(context.Background())
		require.NoError(t, err)
		require.Nil(t, r.EngineRecord)
	})
}

// basalt status on an engine run in the foreground reads the record too:
// the engine id from the running engine's key file, the record through the
// agent's own database, with the same problems as the status tool.
func TestLocalStatusEngineRecord(t *testing.T) {
	t.Parallel()
	local := func(key *string, read EngineRecordReader) StatusReport {
		t.Helper()
		cmds, err := NewCommands("bot", "", "linux", testManager())
		require.NoError(t, err)
		r, err := LocalStatus{
			Errors: testErrors(), LatestGuardVersion: guard.LatestVersion,
			Name: "bot", Commands: cmds, EngineRunning: true, EngineKey: key, EngineRecord: read,
			Probe: &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)},
			Passkeys: func(context.Context) ([]passkey.Credential, error) {
				return []passkey.Credential{{Relying: passkey.Relying{Origin: links.DefaultLocal}}}, nil
			},
			Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
		}.Report(context.Background())
		require.NoError(t, err)
		return r
	}
	id := testEngineID
	r := local(&id, recordOf(false))
	require.Equal(t, engineRecorded, r.EngineRecord.State)
	require.Empty(t, r.Problems)

	r = local(&id, recordOf(true))
	require.Equal(t, engineRevoked, r.EngineRecord.State)
	findProblem(t, r, problemEngineRevoked)

	refused := ""
	r = local(&refused, recordOf(true))
	require.Equal(t, &EngineRecordStatus{State: engineUnknown}, r.EngineRecord, "the key file is refused")
	require.Empty(t, r.Problems)

	require.Nil(t, local(nil, recordOf(true)).EngineRecord, "an engine that is down has none")
}

// notRecorded is a database that holds no row for the engine.
func notRecorded(context.Context, string) (*EngineRecord, error) {
	return nil, nil //nolint:nilnil // a missing row is the answer, not an error
}

// A config refused for the older credentialFile key puts the edit in the
// shim's status, since the engine cannot start on it.
func TestEngineDownStatusNamesTheOldCredentialFileEdit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir": "/s", "agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c/bot.cred"}]}`), 0o600))
	_, cfgErr := config.Load(path)
	cmds, err := NewCommands("bot", path, "linux", testManager())
	require.NoError(t, err)
	r, err := EngineDownStatus(testEngineHost(), "bot", cmds, nil, cfgErr, "test", statusNow)
	require.NoError(t, err)
	require.Len(t, r.Problems, 1)
	require.Contains(t, r.Problems[0].Message, `agent "bot": "credentialFile" now goes inside "store"; replace "credentialFile": "/c/bot.cred" with "store": {"kind": "POSTGRES", "credentialFile": "/c/bot.cred"}`)
}

// After a setup is recorded, status names every active passkey with its
// check code (CONTRACT.md, Connect, The passkey check code); a second key
// shows as a second code.
func TestStatusNamesPasskeysWithCheckCodes(t *testing.T) {
	t.Parallel()
	probe := func() *fakeProbe {
		return &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), latest: &guardmodel.AgentSetup{SetupID: uuid.MustParse(caseRunID), Kind: guardmodel.SetupInstall}}
	}
	statusTool, _ := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)

	one := engineStatus(probe(), 1, nil)(t)
	requireStatusSchema(t, statusTool, one)
	require.Len(t, one.Passkeys.Keys, 1)
	want, err := testCredentials(1)[0].CheckCode()
	require.NoError(t, err)
	require.Equal(t, PasskeyStatus{CredentialID: []byte{1}, CheckCode: want}, one.Passkeys.Keys[0])
	require.Equal(t, "1 passkey is registered, with check code "+want+
		". If the setup page showed you a check code for the passkey it created, it should be one of these. A passkey you did not create means stop and remove it.", one.Passkeys.Summary)

	two := engineStatus(probe(), 2, nil)(t)
	requireStatusSchema(t, statusTool, two)
	require.Len(t, two.Passkeys.Keys, 2)
	require.NotEqual(t, two.Passkeys.Keys[0].CheckCode, two.Passkeys.Keys[1].CheckCode)
	require.Contains(t, two.Passkeys.Summary, "2 passkeys are registered")
	for _, k := range two.Passkeys.Keys {
		require.Contains(t, two.Passkeys.Summary, k.CheckCode)
	}

	agentKind := engineStatus(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), latest: &guardmodel.AgentSetup{SetupID: uuid.MustParse(caseRunID), Kind: guardmodel.SetupAgent}}, 1, nil)(t)
	require.Contains(t, agentKind.Passkeys.Summary, "If the setup page showed you a check code")

	pending := engineStatus(probe(), 1, pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour)))(t)
	require.Len(t, pending.Passkeys.Keys, 1, "status returns the codes whatever the setup's state")
	require.Empty(t, pending.Passkeys.Summary, "the message waits for a recorded setup")

	none := engineStatus(probe(), 0, nil)(t)
	require.Empty(t, none.Passkeys.Keys)
	require.Empty(t, none.Passkeys.Summary)
}

// originKeys answers Passkeys with one key per origin, ids 1, 2, ...
type originKeys struct {
	approvalStore
	origins []string
}

func (k originKeys) Passkeys(context.Context) ([]passkey.Credential, error) {
	out := append([]passkey.Credential(nil), testCredentials(len(k.origins))...) // the shared keys stay as they are
	for i, o := range k.origins {
		out[i].Relying = passkey.Relying{Origin: o}
	}
	return out, nil
}

// An agent whose links open on the portal counts only the portal's
// passkeys: a localhost passkey cannot sign there, so with only that one
// status says NO_PASSKEY with the steps to register one.
func TestStatusCountsOnlyThePagesPasskeys(t *testing.T) {
	t.Parallel()
	report := func(t *testing.T, base string, origins ...string) StatusReport {
		t.Helper()
		return pagesStatus(t, mcpcontract.OperatedByAgent, base, "", origins...)
	}
	const local = "http://localhost:8797"

	onlyLocal := report(t, links.Portal, local)
	require.False(t, onlyLocal.Ready, "no passkey can sign the agent's links")
	require.False(t, onlyLocal.Passkeys.Registered)
	require.Equal(t, 0, *onlyLocal.Passkeys.Active)
	require.Empty(t, onlyLocal.Passkeys.Keys)
	noKey := findProblem(t, onlyLocal, problemNoPasskey)
	require.Equal(t, mcpcontract.SeverityError, noKey.Severity)
	require.Contains(t, noKey.Message, "no passkey is registered on "+links.Portal)
	require.NotEmpty(t, noKey.NextSteps)
	for _, st := range noKey.NextSteps {
		require.NotEqual(t, toolresult.ActorPerson+" "+toolresult.ActionRunCommand, st.Actor+" "+st.Action, "the person never runs a command")
	}

	both := report(t, links.Portal, local, links.Portal)
	require.True(t, both.Ready)
	require.True(t, both.Passkeys.Registered)
	require.Equal(t, 1, *both.Passkeys.Active)
	require.Equal(t, passkey.Bytes{2}, both.Passkeys.Keys[0].CredentialID, "the portal's passkey only")
	for _, p := range both.Problems {
		require.NotEqual(t, problemNoPasskey, p.Code)
	}

	// On local pages it is the other way round, and the setup page's
	// Update link is the person's step.
	localPages := report(t, local, local, links.Portal)
	require.Equal(t, 1, *localPages.Passkeys.Active)
	require.Equal(t, passkey.Bytes{1}, localPages.Passkeys.Keys[0].CredentialID)
	const update = "http://localhost:8797/setup#update"
	onlyPortal := pagesStatus(t, "", local, update, links.Portal)
	require.False(t, onlyPortal.Ready)
	steps := findProblem(t, onlyPortal, problemNoPasskey).NextSteps
	require.Equal(t, toolresult.ActionOpenLink, steps[0].Action)
	require.Equal(t, update, steps[0].URL)
	require.Equal(t, toolresult.ActionEndTurn, steps[1].Action)
}

// pagesStatus is the status of an agent whose links open at base, with
// one passkey per origin and the setup page's Update link update ("" for
// none).
func pagesStatus(t *testing.T, operatedBy, base, update string, origins ...string) StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Core.PagesBase = base
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, originKeys{origins: origins})
	d.Core.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds.UpdateLink(update)
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

// A basalt mcp that tried to start the engine and could not says why in
// status and in every other call, with the log's path.
func TestEngineDownNamesWhyTheStartFailed(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	const why = "basalt mcp could not start the engine: the engine did not start within 15s. Its log is /s/engine.log."
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }, StartFailure: func() string { return why }}

	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, why, "")
	require.NoError(t, err)
	require.Equal(t, problemEngineStartFailed, r.Problems[0].Code, "the start failure comes first")
	require.Equal(t, why, r.Problems[0].Message)
	require.Equal(t, problemEngineUnreachable, r.Problems[1].Code, "the manual step stays")
	require.False(t, r.Ready)

	var query guidance.Tool
	for _, tool := range down.Tools() {
		if tool.Name == "query" {
			query = tool
		}
	}
	_, err = query.Call(context.Background(), json.RawMessage(`{}`))
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te)
	require.Contains(t, te.Message, why)

	// Without a failure nothing is added.
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Equal(t, problemEngineUnreachable, r.Problems[0].Code)
	require.Len(t, r.Problems, 1)
}

func TestStatusStartedBy(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"hand": "HAND", "mcp": "MCP", "crash": "CRASH", "": ""} {
		d := deps()
		d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
		setApprovals(&d, keys{n: 1})
		d.Status.StartedBy = in
		r, err := NewService(d).Status(context.Background())
		require.NoError(t, err)
		require.Equal(t, want, r.Engine.StartedBy, in)
		require.Nil(t, r.Engine.LastStop, "a running engine reports no last stop")
	}
}

func TestEngineDownStatusLastStop(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	dir := t.TempDir()
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}

	r, err := EngineDownStatus(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow)
	require.NoError(t, err)
	require.Nil(t, r.Engine.LastStop, "no file, no last stop")

	require.NoError(t, os.WriteFile(filepath.Join(dir, lastStopFile), []byte("{\"reason\":\"the engine crashed 5 times within 10s; last: exit status 1\\u0007\",\"at\":\"2026-11-20T01:02:03Z\"}"), 0o600))
	r, err = EngineDownStatus(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow)
	require.NoError(t, err)
	require.NotNil(t, r.Engine.LastStop)
	require.Equal(t, "the engine crashed 5 times within 10s; last: exit status 1 ", r.Engine.LastStop.Reason, "unprintable characters are blanked")
	require.Equal(t, time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC), r.Engine.LastStop.At)
	p := findProblem(t, r, problemEngineGaveUp)
	require.Contains(t, p.Message, "the engine crashed 5 times within 10s")
	findProblem(t, r, problemEngineUnreachable)

	// A file that is not a record shows nothing.
	require.NoError(t, os.WriteFile(filepath.Join(dir, lastStopFile), []byte("not json"), 0o600))
	r, err = EngineDownStatus(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow)
	require.NoError(t, err)
	require.Nil(t, r.Engine.LastStop)
}

func TestReadLastStopRefusesASymlinkAndAFifo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"reason":"x","at":"2026-11-20T01:02:03Z"}`), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, lastStopFile)))
	_, ok := ReadLastStop(dir)
	require.False(t, ok, "a symlink is not the record")
	require.NoError(t, os.Remove(filepath.Join(dir, lastStopFile)))
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, lastStopFile), 0o600))
	_, ok = ReadLastStop(dir)
	require.False(t, ok, "a pipe is not the record and does not block")
}

func TestEngineDownStatusHoldOffNamesTheNextTry(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	at := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	rec, err := json.Marshal(servicespec.LastStopFileRecord{
		Reason: "the engine crashed 5 times within 10s; last: exit status 1",
		At:     at, EngineSHA256: laststop.HashEngineJSON(cfgPath),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, lastStopFile), rec, 0o600))
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
	now := at.Add(30 * time.Second)

	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", now, "", cfgPath)
	require.NoError(t, err)
	p := findProblem(t, r, problemEngineGaveUp)
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1. The next try is at 2026-11-21T08:01:00Z.", p.Message)
	// lastStop on the wire stays {reason, at}.
	raw, err := json.Marshal(r.Engine.LastStop)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "engineSha256")
	require.JSONEq(t, `{"reason":"the engine crashed 5 times within 10s; last: exit status 1","at":"2026-11-21T08:00:00Z"}`, string(raw))

	// After the minute, the next-try sentence is gone; the reason stays.
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", at.Add(time.Minute), "", cfgPath)
	require.NoError(t, err)
	p = findProblem(t, r, problemEngineGaveUp)
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1", p.Message)

	// Editing engine.json ends the hold-off message too.
	require.NoError(t, os.WriteFile(cfgPath, []byte("v2\n"), 0o600))
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", now, "", cfgPath)
	require.NoError(t, err)
	p = findProblem(t, r, problemEngineGaveUp)
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1", p.Message)
}

func TestEngineDownToolNamesHoldOff(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	at := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	rec, err := json.Marshal(servicespec.LastStopFileRecord{
		Reason: "the engine crashed 5 times within 10s; last: exit status 1",
		At:     at, EngineSHA256: laststop.HashEngineJSON(cfgPath),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, lastStopFile), rec, 0o600))
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
	now := at.Add(30 * time.Second)
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Config: cfg, ConfigPath: cfgPath, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}

	_, callErr := down.unreachable("query")(context.Background(), nil)
	require.Error(t, callErr)
	require.Contains(t, callErr.Error(), "the engine stopped and was not restarted: the engine crashed 5 times within 10s")
	require.Contains(t, callErr.Error(), "The next try is at 2026-11-21T08:01:00Z")
}
