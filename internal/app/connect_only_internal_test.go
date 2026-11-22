package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// connectOnlyCode is the contract's connect-only fixture
// (api/mcp/setup/setup-code.fixtures.json).
const connectOnlyCode = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDg6xTUmHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8.mvDCHA"

// connectOnlyMade is the fixture's setupId time (its UUIDv7). Tests use a
// clock just after it, so a waiting agent's status does not depend on the
// wall clock: the signed code expires 24 hours after this time.
var connectOnlyMade = time.UnixMilli(0x01a1f78c52b8).UTC()

// connectOnlyEnv is an engine.json whose agent bot waits for its database's
// address, with its .secret.
func connectOnlyEnv(t *testing.T) (agentEnv, config.Agent) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	cred := filepath.Join(dir, "agents", "bot.url")
	a := config.Agent{Name: "bot", OSUser: "bot", Store: config.PostgresStore(cred), Setup: &config.Setup{
		SetupID: "01a1f78c-52b8-7c3a-9f00-0000000000e1", Kind: "INSTALL", GuardVersion: 16, ExpiresAt: "2026-11-20T06:12:11Z",
		Code: connectOnlyCode, Fingerprint: "734b aaea 804e 1065 4148", AwaitingAddress: true,
	}}
	cfg := config.Config{SocketDir: "/run/basalt", Agents: []config.Agent{a}}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))
	require.NoError(t, config.WriteFile(config.SecretPath(cred, "bot"), []byte("pw\n")))
	return agentEnv{cfg: cfg, configPath: cfgPath, handoff: HandoffOptions{
		Now: func() time.Time { return connectOnlyMade.Add(time.Minute) },
	}}, a
}

// Waiting for the address: the agent is served by the connect-only
// runtime, and .secret stays.
func TestConnectOnlyAgentWaits(t *testing.T) {
	t.Parallel()
	env, a := connectOnlyEnv(t)
	waiting, err := connectOnlyAgent(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.True(t, waiting)
	require.FileExists(t, config.SecretPath(a.Store.CredentialFile, "bot"))

	rt, err := newConnectOnlyRuntime(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Nil(t, rt.svc, "no service, no pool")
	require.NotNil(t, rt.run)
	names := map[string]bool{}
	for _, tool := range rt.tools {
		names[tool.Name] = true
	}
	require.True(t, names["status"])
	require.True(t, names["confirm_database"])
}

// An engine started as root serves the waiting agent
// degraded with ENGINE_AS_ROOT, never collects, and touches none of its
// files, even a confirmation it stopped in; it does not stop.
func TestConnectOnlyAgentAsRootDegrades(t *testing.T) {
	t.Parallel()
	env, a := connectOnlyEnv(t)
	env.asRoot = true
	require.NoError(t, config.WriteFile(a.Store.CredentialFile, []byte("postgres://x@db.example.com/app\n")))
	waiting, err := connectOnlyAgent(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.True(t, waiting, "as root, an interrupted YES is left for an engine run as the agent's user")
	require.FileExists(t, config.SecretPath(a.Store.CredentialFile, "bot"))
	cfg, err := config.Load(env.configPath)
	require.NoError(t, err)
	require.True(t, cfg.Agents[0].Setup.AwaitingAddress)

	require.NoError(t, os.Remove(a.Store.CredentialFile))
	rt, err := newConnectOnlyRuntime(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	var raw []byte
	for _, tool := range rt.tools {
		if tool.Name == "status" {
			out, err := tool.Call(context.Background(), json.RawMessage(`{}`))
			require.NoError(t, err)
			raw, err = json.Marshal(out)
			require.NoError(t, err)
		}
	}
	var st struct {
		Problems []struct {
			Code string `json:"code"`
		} `json:"problems"`
	}
	require.NoError(t, json.Unmarshal(raw, &st))
	codes := make([]string, 0, len(st.Problems))
	for _, p := range st.Problems {
		codes = append(codes, p.Code)
	}
	require.Contains(t, codes, "ENGINE_AS_ROOT")
	require.FileExists(t, config.SecretPath(a.Store.CredentialFile, "bot"))
}

// The engine stopped after the YES wrote the credential and before it
// cleared awaitingAddress: only that YES writes the file, so the engine
// finishes it and serves the agent on its credential.
func TestConnectOnlyAgentFinishesAnInterruptedYes(t *testing.T) {
	t.Parallel()
	env, a := connectOnlyEnv(t)
	require.NoError(t, config.WriteFile(a.Store.CredentialFile, []byte("postgres://basalt_agent_lead_bot:pw@db.example.com:5432/app?sslmode=verify-full\n")))
	waiting, err := connectOnlyAgent(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.False(t, waiting)
	_, err = os.Lstat(config.SecretPath(a.Store.CredentialFile, "bot"))
	require.True(t, os.IsNotExist(err), ".secret removed")
	cfg, err := config.Load(env.configPath)
	require.NoError(t, err)
	require.False(t, cfg.Agents[0].Setup.AwaitingAddress)
	require.Equal(t, a.Setup.SetupID, cfg.Agents[0].Setup.SetupID, "the setup stays pending until the database shows it")
}

// A refused setup is served by the connect-only runtime, whatever files
// are there.
func TestConnectOnlyAgentRefused(t *testing.T) {
	t.Parallel()
	env, a := connectOnlyEnv(t)
	a.Setup.AwaitingAddress, a.Setup.Refused = false, true
	waiting, err := connectOnlyAgent(env, a, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.True(t, waiting)
}

// A reload asked for while the engine waits makes the restart trigger
// return, and marks it a reload.
func TestUpgradeOrReload(t *testing.T) {
	t.Parallel()
	reload, reloading := make(chan struct{}, 1), make(chan struct{})
	up := upgradeOrReload(nil, reload, reloading)
	reload <- struct{}{}
	require.NoError(t, up(t.Context()))
	select {
	case <-reloading:
	default:
		t.Fatal("not marked a reload")
	}
}
