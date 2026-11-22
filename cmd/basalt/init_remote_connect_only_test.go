package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// connectOnlyArgs make a connect-only code: a new engine is
// agent-operated with the Vault on.
var connectOnlyArgs = []string{"--agent", "bot"}

// connectOnlyConfig is a config path whose state directory exists: the
// tests' host runs init as root, which never makes it, and a connect-only
// code needs the engine's key there.
func connectOnlyConfig(t *testing.T) string {
	t.Helper()
	return withState(t, tempConfig(t))
}

// secretOf reads the agent's .secret next to the config and checks its mode.
func secretOf(t *testing.T, cfg string) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(cfg), "agents", "bot"+secretSuffix)
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func secretPathOf(cfg string) string {
	return filepath.Join(filepath.Dir(cfg), "agents", "bot"+secretSuffix)
}

// editSetup changes the agent's pending setup in engine.json.
func editSetup(t *testing.T, cfg string, edit func(s *config.Setup)) {
	t.Helper()
	editConfig(t, cfg, func(c *config.Config) { edit(c.Agents[0].Setup) })
}

// connectOnlyWithPrefix is a fresh connect-only INSTALL code for the bot
// whose saved flags name the role prefix, so tests sharing a database
// server keep their roles apart.
func connectOnlyWithPrefix(t *testing.T, cfg, prefix string) remoteRun {
	t.Helper()
	remote(t, cfg, connectOnlyArgs...)
	require.NoError(t, os.Remove(secretPathOf(cfg)))
	editConfig(t, cfg, func(c *config.Config) {
		c.Agents[0].Setup = nil
		c.Agents[0].InitArgs = []string{"--agent=bot", "--" + flagAllTables + "=true", "--prefix=" + prefix}
	})
	r := remote(t, cfg, connectOnlyArgs...)
	require.Equal(t, prefix, r.payload.Prefix)
	require.Equal(t, string(setupcode.KindInstall), r.res.Kind)
	return r
}

// A new engine's first run makes a connect-only code: no target, the
// engine's key, every table in public, the password in .secret and nowhere
// else, and only the connect link handed over.
func TestInitRemoteMakesAConnectOnlyCode(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	r := remote(t, cfg, connectOnlyArgs...)

	require.True(t, r.res.ConnectOnly)
	require.Equal(t, string(setupcode.KindInstall), r.res.Kind)
	require.True(t, r.payload.ConnectOnly())
	require.Nil(t, r.payload.Target)
	require.NotNil(t, r.payload.Engine, "the engine collects the address with its key")
	require.Equal(t, &setupcode.AllTables{Schemas: []string{"public"}}, r.payload.Agent.AllTables)
	require.Nil(t, r.payload.Agent.Write)
	require.Equal(t, guard.DefaultPrefix, r.payload.Prefix)

	password := secretOf(t, cfg)
	requireVerifierOf(t, r.payload.Agent.Verifier, password)
	requireNoSecret(t, r, cfg, password)
	require.NoFileExists(t, r.credFile, "no address, so no credential file")
	require.Equal(t, mcpcontract.OperatedByAgent, r.cfg.OperatedBy, "--remote makes a new engine agent-operated")
	require.Equal(t, config.VaultOn, r.cfg.Vault)
	s := r.cfg.Agents[0].Setup
	require.True(t, s.AwaitingAddress)
	require.False(t, s.Refused)
	require.Contains(t, r.cfg.Agents[0].InitArgs, "--"+flagAllTables+"=true")

	// The link and the fingerprint, no laptop command.
	require.Equal(t, links.Portal+"/connect#"+r.res.Code, r.res.ConnectURL)
	pm := r.res.PersonMessage
	require.Contains(t, pm, r.res.Fingerprint)
	require.Contains(t, pm, "connection string")
	require.NotContains(t, pm, "--setup-code")
	require.NoError(t, agent.CheckPersonMessage(pm), pm)
	mcptest.Require(t, pm, []mcp.Link{{Label: agent.LabelConnect, URL: r.res.ConnectURL}})

	// Text: the link and the fingerprint, no laptop command.
	require.Contains(t, r.stdout, "\n\n"+r.res.ConnectURL+"\n\n")
	require.Contains(t, r.stdout, "Setup fingerprint: "+r.res.Fingerprint+"\n")
	require.NotContains(t, r.stdout, "--setup-code")
}

// While the code waits and has not expired, a re-run prints it again, so
// .secret is never replaced while its code may already have run.
func TestInitRemoteConnectOnlyWhileWaiting(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	first := remote(t, cfg, connectOnlyArgs...)
	password := secretOf(t, cfg)

	again := remote(t, cfg, connectOnlyArgs...)
	require.True(t, again.res.Reused)
	require.Equal(t, first.res.Code, again.res.Code)
	require.True(t, again.res.ConnectOnly)
	require.Equal(t, password, secretOf(t, cfg), "nothing changed")
}

// The recoveries need no flag (DATABASE_REFUSED, SETUP_EXPIRED,
// ADDRESS_INVALID, a lost .secret): the next run forgets the pending setup
// and makes a recovery code, AGENT with a new password and its verifier,
// still connect-only.
func TestInitRemoteConnectOnlyRecoveryCodes(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(t *testing.T, cfg string){
		"expired": func(t *testing.T, cfg string) {
			t.Helper()
			editSetup(t, cfg, func(s *config.Setup) { s.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
		},
		"refused": func(t *testing.T, cfg string) {
			t.Helper()
			editSetup(t, cfg, func(s *config.Setup) { s.AwaitingAddress, s.Refused = false, true })
		},
		"address invalid": func(t *testing.T, cfg string) {
			t.Helper()
			editSetup(t, cfg, func(s *config.Setup) { s.AddressInvalid = true })
		},
		"secret gone": func(t *testing.T, cfg string) { t.Helper(); require.NoError(t, os.Remove(secretPathOf(cfg))) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := connectOnlyConfig(t)
			first := remote(t, cfg, connectOnlyArgs...)
			old := secretOf(t, cfg)
			edit(t, cfg)
			again := remote(t, cfg, connectOnlyArgs...)
			require.False(t, again.res.Reused)
			require.NotEqual(t, first.res.SetupID, again.res.SetupID)
			require.Equal(t, string(setupcode.KindAgent), again.res.Kind)
			require.True(t, again.payload.ConnectOnly())
			require.NotNil(t, again.payload.Agent.AllTables)
			password := secretOf(t, cfg)
			require.NotEqual(t, old, password)
			requireVerifierOf(t, again.payload.Agent.Verifier, password)
			s := again.cfg.Agents[0].Setup
			require.True(t, s.AwaitingAddress)
			require.False(t, s.Refused)
			require.False(t, s.AddressInvalid)
		})
	}
}

// A connect-only code needs an agent-operated engine with the Vault on:
// a config another init made otherwise is refused, nothing written.
func TestInitRemoteConnectOnlyNeedsTheConnectPath(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		edit func(c *config.Config)
		want string
	}{
		"person-operated": {func(c *config.Config) { c.OperatedBy = "PERSON"; c.Vault = "" }, "this engine is person-operated"},
		"vault off":       {func(c *config.Config) { c.Vault = config.VaultOff }, "this engine has the Vault off"},
	} {
		cfg := connectOnlyConfig(t)
		remote(t, cfg, connectOnlyArgs...)
		editConfig(t, cfg, tc.edit)
		old := secretOf(t, cfg)
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, connectOnlyArgs...)...)
		require.Equal(t, exitError, r.code, "%s: %s", name, r.stderr)
		require.Contains(t, r.stderr, tc.want, name)
		require.Equal(t, old, secretOf(t, cfg), name)
	}
}

// A connect-only code needs the engine's key: without it init refuses,
// nothing written.
func TestInitRemoteConnectOnlyNeedsTheEngineKey(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	state := filepath.Join(filepath.Dir(cfg), stateDirName)
	require.NoError(t, os.WriteFile(filepath.Join(state, channel.KeyFileName), []byte("not a key"), 0o600))

	r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, connectOnlyArgs...)...)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "a setup code for the connect page needs the engine's key, and basalt cannot read or make it as this user")
	require.Contains(t, r.stderr, "Run basalt init --remote as the engine's OS user")
	require.NoFileExists(t, cfg)
	require.NoFileExists(t, secretPathOf(cfg))
}

// A recovery code asks for what the agent's saved flags ask for (tables,
// prefix, timeout).
func TestInitRemoteRecoveryKeepsTheSavedRequest(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	first := remote(t, cfg, connectOnlyArgs...)
	editConfig(t, cfg, func(c *config.Config) {
		c.Agents[0].InitArgs = []string{"--agent=bot", "--" + flagAllTables + "=true", "--prefix=acme", "--statement-timeout=45s"}
		c.Agents[0].Setup.Refused = true
	})
	saved, err := config.Load(cfg)
	require.NoError(t, err)
	again := remote(t, cfg, connectOnlyArgs...)
	require.NotEqual(t, first.res.SetupID, again.res.SetupID)
	require.Equal(t, string(setupcode.KindAgent), again.res.Kind)
	require.Equal(t, "acme", again.payload.Prefix)
	require.Equal(t, int64(45000), again.payload.Agent.StatementTimeoutMs)
	require.NotNil(t, again.payload.Agent.AllTables)
	require.Equal(t, mcpcontract.OperatedByAgent, again.cfg.OperatedBy)
	require.Subset(t, again.cfg.Agents[0].InitArgs, saved.Agents[0].InitArgs)
}

// A connect link over the engine's linkBudget is left out: the message
// names the connect page without a URL.
func TestInitRemoteConnectOnlyOverTheBudget(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	remote(t, cfg, connectOnlyArgs...)
	editConfig(t, cfg, func(c *config.Config) { b := 100; c.LinkBudget = &b })

	r := remote(t, cfg, connectOnlyArgs...)
	require.True(t, r.res.ConnectOnly)
	require.Empty(t, r.res.ConnectURL)
	require.NotContains(t, r.res.PersonMessage, "https://")
	require.Contains(t, r.res.PersonMessage, "portal.basaltvault.app/connect")
	require.NoError(t, agent.CheckPersonMessage(r.res.PersonMessage), r.res.PersonMessage)
	mcptest.Require(t, r.res.PersonMessage, nil)
	require.Contains(t, r.stdout, "\n\n"+r.res.Code+"\n\n")
	require.NotContains(t, r.stdout, "--setup-code")
}

// Not as root, the path a bot's engine user takes: init makes the engine's
// key itself and writes .secret by path.
func TestInitRemoteConnectOnlyNotAsRoot(t *testing.T) {
	t.Parallel()
	// Not as root the sockets sit next to the config: a short directory,
	// so the socket path fits.
	dir, err := os.MkdirTemp("/tmp", "bt")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "engine.json")
	e := remoteEnv{host: newFakeHost(t), login: refusedLogin, probe: noNetworkProbe, noNetwork: true}
	r := remoteWith(t, e, cfg, connectOnlyArgs...)
	require.True(t, r.res.ConnectOnly)
	require.NotNil(t, r.payload.Engine)
	requireVerifierOf(t, r.payload.Agent.Verifier, secretOf(t, cfg))
	require.FileExists(t, filepath.Join(filepath.Dir(cfg), stateDirName, channel.KeyFileName))

	editSetup(t, cfg, func(s *config.Setup) { s.Refused = true })
	again := remoteWith(t, e, cfg, connectOnlyArgs...)
	require.NotEqual(t, r.res.SetupID, again.res.SetupID)
	requireVerifierOf(t, again.payload.Agent.Verifier, secretOf(t, cfg))
}
