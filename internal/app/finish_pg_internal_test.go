package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// These tests run the engine's agent runtime against a real Postgres
// through a setup from the laptop (CONTRACT.md, Setup from your laptop): the
// engine serves only status until the database, read with the agent's own
// credential, shows the setup recorded; then status clears the setup from
// engine.json and the tools are served, with no restart.

var demoTables = []string{"public.leads"}

// remoteAgent is an agent as basalt init --remote leaves it: its credential
// file, and engine.json with its pending setup.
type remoteAgent struct {
	dir, cfgPath, credFile string
	setup                  config.Setup
	setupID                uuid.UUID
	expires                time.Time
}

func newRemoteAgent(t *testing.T, dsn, kind string) remoteAgent {
	t.Helper()
	dir := t.TempDir()
	r := remoteAgent{dir: dir, cfgPath: filepath.Join(dir, "engine.json"), credFile: filepath.Join(dir, "bot.url")}
	require.NoError(t, config.WriteFile(r.credFile, []byte(dsn+"\n")))
	r.setupID = uuid.Must(uuid.NewV7())
	r.expires = time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	r.setup = config.Setup{
		SetupID: r.setupID.String(), Kind: kind, GuardVersion: guard.LatestVersion(),
		ExpiresAt: r.expires.Format(time.RFC3339), Code: "basalt-setup.1.abc.def", Fingerprint: "a1b2 c3d4 e5f6 0718 293a",
	}
	setup := r.setup
	require.NoError(t, config.UpsertAgent(r.cfgPath, config.Settings{SocketDir: "/run/basalt", StateDir: dir, OperatedBy: mcpcontract.OperatedByAgent, PagesURL: links.Portal},
		config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore(r.credFile), Setup: &setup}))
	return r
}

// start is the engine's runtime for the agent, as Run builds it.
func (r remoteAgent) start(t *testing.T) agentRuntime {
	t.Helper()
	cfg, err := config.Load(r.cfgPath)
	require.NoError(t, err)
	env := agentEnv{cfg: cfg, configPath: r.cfgPath, pagesBase: links.DefaultLocal, stateDir: r.dir, pins: &chainpin.Memory{}}
	rt, err := newAgentRuntime(context.Background(), env, cfg.Agents[0], slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(rt.close)
	return rt
}

// configSetup is the agent's pending setup in engine.json now.
func (r remoteAgent) configSetup(t *testing.T) *config.Setup {
	t.Helper()
	cfg, err := config.Load(r.cfgPath)
	require.NoError(t, err)
	return cfg.Agents[0].Setup
}

func (r remoteAgent) record(t *testing.T, d *guardtest.DB, kind string) {
	t.Helper()
	_, err := guard.RecordSetup(context.Background(), d.Admin, d.Names,
		guardmodel.Setup{ID: r.setupID, Kind: kind, Agent: "bot", GuardVersion: guard.LatestVersion(), ExpiresAt: r.expires})
	require.NoError(t, err)
}

func verifierOf(t *testing.T, password string) string {
	t.Helper()
	v, err := setupcode.NewVerifier(password)
	require.NoError(t, err)
	return v
}

func problemCodes(r guidance.StatusReport) []string {
	out := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

func TestALaptopInstallIsFinishedByStatusWithoutARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	pw := guard.NewPassword()
	dsn, err := guard.AgentConnString(d.URL, role, pw)
	require.NoError(t, err)
	r := newRemoteAgent(t, dsn, guardmodel.SetupInstall)
	rt := r.start(t)

	// Before the person's laptop: every tool but status is held.
	var se *guidance.SetupError
	require.ErrorAs(t, rt.svc.Admit(ctx), &se)
	st, err := rt.svc.status.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, "PENDING", st.Setup.State)
	require.Equal(t, []string{"SETUP_NOT_RUN"}, problemCodes(st))

	// The guard and the role alone are not the setup: until the code is
	// recorded the engine clears nothing.
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Verifier: verifierOf(t, pw), CreateOnly: true, Write: demoTables, Read: demoTables})
	require.ErrorAs(t, rt.svc.Admit(ctx), &se)
	require.NotNil(t, r.configSetup(t))

	// The laptop records the code in the install's transaction.
	r.record(t, d, guardmodel.SetupInstall)
	st, err = rt.svc.status.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, guidance.SetupStatus{State: "DONE", SetupID: r.setup.SetupID, Kind: guardmodel.SetupInstall}, st.Setup)
	require.Equal(t, []string{"NO_PASSKEY"}, problemCodes(st), "no passkey yet: a usual problem, not an unfinished setup")
	require.Equal(t, "AGENT", st.Problems[0].NextSteps[0].Actor, "the agent makes the code that registers one")
	require.False(t, st.Ready, "not ready until a passkey can sign; the tools are still served")
	require.Nil(t, r.configSetup(t), "cleared from engine.json")

	// Served, with no restart.
	require.NoError(t, rt.svc.Admit(ctx))
	_, err = rt.svc.agent.StartRun(ctx, "check the leads", uuid.Nil)
	require.NoError(t, err)
}

func TestARotatedCredentialIsPromotedWhenItsSetupIsRecorded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, demoTables)
	r := newRemoteAgent(t, a.URL, guardmodel.SetupAgent)
	pw2 := guard.NewPassword()
	pending, err := guard.AgentConnString(d.URL, a.Role, pw2)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(r.credFile+handoff.PendingSuffix, []byte(pending+"\n")))
	rt := r.start(t)

	st, err := rt.svc.status.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, "PENDING", st.Setup.State)
	require.Contains(t, problemCodes(st), "SETUP_CHANGE_PENDING")

	// The laptop rotates the password to the one in .pending and records
	// the code: the engine's own password stops working.
	d.Init(t, guardmodel.AgentSpec{Name: "bot", Verifier: verifierOf(t, pw2), Write: demoTables, Read: demoTables})
	r.record(t, d, guardmodel.SetupAgent)

	st, err = rt.svc.status.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, "DONE", st.Setup.State)
	require.NotContains(t, problemCodes(st), "CREDENTIAL_REJECTED", "the pool logs in with the promoted password")
	require.Equal(t, guardmodel.GuardOK, st.Guard.State)
	got, err := os.ReadFile(r.credFile)
	require.NoError(t, err)
	require.Equal(t, pending+"\n", string(got))
	_, err = os.Lstat(r.credFile + handoff.PendingSuffix)
	require.True(t, os.IsNotExist(err), "moved over the credential file")
	require.Nil(t, r.configSetup(t))
	_, err = rt.svc.agent.StartRun(ctx, "check the leads", uuid.Nil)
	require.NoError(t, err)
}

// The engine takes the agent's lock, the one basalt init --remote holds
// while it writes a new code: while it is held nothing is cleared, and the
// next status finishes the setup.
func TestTheSetupIsNotClearedWhileInitHoldsTheLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", demoTables, demoTables)
	r := newRemoteAgent(t, a.URL, guardmodel.SetupUpgrade)
	rt := r.start(t)
	_, err := guard.RecordSetup(ctx, d.Admin, d.Names,
		guardmodel.Setup{ID: r.setupID, Kind: guardmodel.SetupUpgrade, GuardVersion: guard.LatestVersion(), ExpiresAt: r.expires})
	require.NoError(t, err)

	unlock, err := config.LockFile(r.credFile + handoff.LockSuffix)
	require.NoError(t, err)
	_, err = rt.svc.status.Status(ctx)
	require.NoError(t, err)
	require.NotNil(t, r.configSetup(t), "locked: nothing cleared")
	unlock()

	require.NoError(t, rt.svc.AdmitTick(ctx))
	require.Nil(t, r.configSetup(t), "the heartbeat finishes it")
}
