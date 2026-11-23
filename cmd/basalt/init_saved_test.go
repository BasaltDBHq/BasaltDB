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

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

func TestServiceInstallRefusesAConnectionURLInitArg(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
	require.NoError(t, os.WriteFile(cfg, []byte("{}\n"), 0o600))
	spec := osservice.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: "basalt"}
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
	spec := osservice.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
	a := agentInstall{name: "bot", osUser: "tester", keepCredential: true, initArgs: []string{"--agent=bot"}}

	_, err := keptCredentialSpec(spec, a, false)
	require.ErrorContains(t, err, "--rotate-password", "a missing credential file is refused")

	cred := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	require.NoError(t, config.WriteFile(cred, []byte("postgres://r:p@h/d\n")))
	got, err := keptCredentialSpec(spec, a, false)
	require.NoError(t, err)
	// The kept file is written back unchanged by the install, which owns it
	// to the engine user, so a changed user can still read it.
	require.Len(t, got.Files, 2)
	require.Equal(t, cred, got.Files[1].Path)
	require.Equal(t, "postgres://r:p@h/d\n", string(got.Files[1].Content))
	require.NotContains(t, string(got.Files[0].Content), `"initArgs"`, "--init-arg is never saved")
}

// An agent that waits for its database's address (a connect-only setup
// code) has no credential file yet: the install places it without one and
// keeps its pending setup in the config.
func TestKeptCredentialSpecForAWaitingAgent(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	setup := &config.Setup{
		SetupID: "01a1f78c-52b8-7c3a-9f00-0000000000e1", Kind: "INSTALL", GuardVersion: 16, ExpiresAt: "2026-11-20T06:12:11Z",
		Code: connectOnlyFixtureCode, Fingerprint: "734b aaea 804e 1065 4148", AwaitingAddress: true,
	}
	cred := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	raw, err := json.Marshal(config.Config{SocketDir: "/run/basalt", Agents: []config.Agent{{Name: "bot", OSUser: "tester", Store: config.PostgresStore(cred), Setup: setup}}})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
	spec := osservice.Spec{GOOS: "linux", Binary: "/b", ConfigPath: cfg, User: me(t)}
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

// connectOnlyFixtureCode is the contract's connect-only fixture
// (api/mcp/setup/setup-code.fixtures.json).
const connectOnlyFixtureCode = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDg6xTUmHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8.mvDCHA"
