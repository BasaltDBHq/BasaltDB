package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

func TestSavedArgsKeepOnlyWhatInitNeedsAgain(t *testing.T) {
	t.Parallel()
	f := initFlags{
		agent: "bot", write: "public.leads", read: "public.notes", prefix: guard.DefaultPrefix, osUser: "iman",
		configPath: "/etc/basalt/engine.json", socketDir: config.DefaultSocketDir("linux"),
		engineUser: "basalt", passkeyOrigin: "http://localhost:8787", agentRLS: AgentRLSAllRows,
		credFile: "/etc/basalt/agents/bot.url", yes: true, dryRun: true, skipPasskey: true, rotatePassword: true,
	}
	f.spec.StatementTimeout = guard.DefaultStatementTimeout
	f.passkeyLabel = "laptop"
	require.Equal(t, []string{
		"--agent=bot", "--write=public.leads", "--read=public.notes", "--os-user=iman", "--agent-rls=all-rows",
	}, f.savedArgs("linux"), "defaults and one-shot flags are not saved")

	f.prefix, f.socketDir, f.engineUser = "acme", "/home/iman/basalt/run", "svc"
	f.credFile = "/home/iman/secrets/bot.url"
	f.spec.StatementTimeout = 5e9
	f.passkeyOrigin = "https://basaltvault.app"
	got := f.savedArgs("linux")
	require.Contains(t, got, "--prefix=acme")
	require.Contains(t, got, "--socket-dir=/home/iman/basalt/run")
	require.Contains(t, got, "--engine-user=svc")
	require.Contains(t, got, "--credential-file=/home/iman/secrets/bot.url")
	require.Contains(t, got, "--statement-timeout=5s")
	require.Contains(t, got, "--passkey-origin=https://basaltvault.app")
}

func TestInitRefusesSavingASecret(t *testing.T) {
	t.Parallel()
	f := initFlags{
		agent: "bot", osUser: "iman", configPath: "/etc/basalt/engine.json", prefix: guard.DefaultPrefix,
		engineUser: "basalt", write: "postgres://u:p@h/db", socketDir: config.DefaultSocketDir("linux"),
	}
	_, err := f.commands("linux")
	require.Error(t, err)
}

// TestInitSavesFlagsWithoutSecrets: init writes initArgs to engine.json, and
// they reproduce the same plan.
func TestInitSavesFlagsWithoutSecrets(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	initAgent(t, d, cfgPath)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	saved := cfg.Agents[0].InitArgs
	require.Equal(t, []string{
		"--agent=bot", "--write=public.leads", "--prefix=" + d.Names.Prefix, "--os-user=tester",
	}, saved)

	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	for _, secret := range []string{d.URL, "postgres://", "password", "basalt@"} {
		require.NotContains(t, string(raw), secret, "engine.json holds no secret")
	}

	env := map[string]string{envAdminURL: d.URL}
	orig := cli(t, env, "", "init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", cfgPath, "--os-user", "tester", "--dry-run")
	require.Equal(t, exitOK, orig.code, orig.stderr)
	replay := cli(t, env, "", append(append([]string{"init"}, saved...), "--config", cfgPath, "--dry-run")...)
	require.Equal(t, exitOK, replay.code, replay.stderr)
	require.Equal(t, orig.stdout, replay.stdout, "the saved flags reproduce the same plan")
}

// TestInitAgainKeepsTheEngineConnection: a second init leaves the
// password, so the credential the engine holds still works.
func TestInitAgainKeepsTheEngineConnection(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	dsn := strings.TrimSpace(string(b))

	stderr := initOut(t, d, cfgPath)
	require.NotContains(t, stderr, "restart")
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err, "the old credential still works")
	conn.Close(ctx)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, dsn, strings.TrimSpace(string(after)))
}

func TestRotatePasswordBreaksTheOldCredentialAndPrintsTheRestart(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	oldDSN := strings.TrimSpace(string(b))

	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", cfgPath, "--os-user", "tester", "--yes", "--skip-passkey", "--rotate-password")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "restart the engine")
	require.Contains(t, r.stderr, "basalt engine --config "+cfgPath)

	ctx := context.Background()
	_, err = pgdial.Connect(ctx, oldDSN)
	require.Error(t, err, "the old credential stops working")
	nb, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEqual(t, oldDSN, strings.TrimSpace(string(nb)))
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(nb)))
	require.NoError(t, err)
	conn.Close(ctx)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	for _, a := range cfg.Agents[0].InitArgs {
		require.NotContains(t, a, "rotate", "--rotate-password is one-shot")
	}
}

func TestServiceInstallRefusesAConnectionURLInitArg(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
	require.NoError(t, os.WriteFile(cfg, []byte("{}\n"), 0o600))
	spec := service.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: "basalt"}
	for _, bad := range []string{"--write=postgres://u:p@h/db", "--os-user=password=x", "--database-url=x", "bot"} {
		_, err := agentSpecFromStdin(strings.NewReader("postgres://a:b@h/d\n"), spec,
			agentInstall{name: "bot", osUser: "tester", initArgs: []string{"--agent=bot", bad}}, true, false)
		require.Error(t, err, bad)
	}
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	require.Equal(t, "{}\n", string(raw), "engine.json is left unchanged")
}

func TestServiceInstallRefusesKeepCredentialWithStdin(t *testing.T) {
	t.Parallel()
	var out, errb bytes.Buffer
	code := runService(context.Background(), []string{
		"install", "--agent", "bot", "--os-user", "x",
		"--keep-credential", "--credential-stdin", "--dry-run",
	}, stdio{in: strings.NewReader(""), out: &out, err: &errb})
	require.Equal(t, exitUsage, code)
}

func TestKeptCredentialSpec(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	spec := service.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
	a := agentInstall{name: "bot", osUser: "tester", keepCredential: true, initArgs: []string{"--agent=bot"}}

	_, err := keptCredentialSpec(spec, a, false)
	require.ErrorContains(t, err, "--rotate-password", "a missing credential file is refused")

	cred := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	require.NoError(t, config.WriteFile(cred, []byte("postgres://r:p@h/d\n")))
	got, err := keptCredentialSpec(spec, a, false)
	require.NoError(t, err)
	// The kept file is written back unchanged by the install, which owns it
	// to --user, so a changed --user can still read it.
	require.Len(t, got.Files, 2)
	require.Equal(t, cred, got.Files[1].Path)
	require.Equal(t, "postgres://r:p@h/d\n", string(got.Files[1].Content))
	require.Contains(t, string(got.Files[0].Content), `"initArgs"`)
}

// An agent that waits for its database's address (a connect-only setup
// code) has no credential file yet: the install places it without one and
// keeps its pending setup in the config.
func TestKeptCredentialSpecForAWaitingAgent(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	setup := &config.Setup{
		SetupID: "01a1f78c-52b8-7c3a-9f00-0000000000e1", Kind: "INSTALL", GuardVersion: 16, ExpiresAt: "2026-11-21T06:02:11Z",
		Code: connectOnlyFixtureCode, Fingerprint: "d48b ee66 a1d9 d005 1f63", AwaitingAddress: true,
	}
	cred := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	raw, err := json.Marshal(config.Config{SocketDir: "/run/basalt", Agents: []config.Agent{{Name: "bot", OSUser: "tester", Store: config.PostgresStore(cred), Setup: setup}}})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
	spec := service.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
	a := agentInstall{name: "bot", osUser: "tester", keepCredential: true, initArgs: []string{"--agent=bot"}}

	_, err = keptCredentialSpec(spec, a, false)
	require.ErrorContains(t, err, ".secret", "the engine's user must own the password the YES writes")
	require.NoError(t, config.WriteFile(config.SecretPath(cred, "bot"), []byte("pw\n")))
	got, err := keptCredentialSpec(spec, a, false)
	require.NoError(t, err)
	require.Len(t, got.Files, 1, "no credential file is written")
	dry, err := keptCredentialSpec(spec, a, true)
	require.NoError(t, err)
	require.Len(t, dry.Files, 1, "a dry run shows the same plan")
	var written config.Config
	require.NoError(t, json.Unmarshal(got.Files[0].Content, &written))
	require.Equal(t, setup, written.Agents[0].Setup, "the pending setup stays")

	// Not waiting (no connect-only setup): still refused.
	raw, err = json.Marshal(config.Config{SocketDir: "/run/basalt", Agents: []config.Agent{{Name: "bot", OSUser: "tester", Store: config.PostgresStore(cred)}}})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
	_, err = keptCredentialSpec(spec, a, false)
	require.ErrorContains(t, err, "--rotate-password")
}

// A mistyped --credential-file must not rotate the password.
func TestInitRefusesAMissingCredentialFileForAnExistingRole(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", cfgPath, "--os-user", "tester", "--yes", "--skip-passkey",
		"--credential-file", filepath.Join(t.TempDir(), "typo.url"))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "--rotate-password")
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err, "the password was not rotated")
	conn.Close(ctx)
}

// connectOnlyFixtureCode is the contract's connect-only fixture
// (api/mcp/setup/setup-code.fixtures.json).
const connectOnlyFixtureCode = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDgmxTXGHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8._9xzIw"
