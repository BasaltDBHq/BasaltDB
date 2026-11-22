package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/connecttest"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// connectOnlyArgs make a connect-only code: an agent-operated engine (the
// Vault on by default), no --database-url.
var connectOnlyArgs = []string{"--agent", "bot", "--all-tables", "--operated-by", "agent"}

// connectOnlyConfig is a config path whose state directory exists: the
// tests' host runs init as root, which never makes it, and a connect-only
// code needs the engine's key there.
func connectOnlyConfig(t *testing.T) string {
	t.Helper()
	cfg := tempConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Join(filepath.Dir(cfg), stateDirName), 0o700))
	return cfg
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
	c, err := config.Load(cfg)
	require.NoError(t, err)
	edit(c.Agents[0].Setup)
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
}

// Without --database-url, an agent-operated engine with the Vault on makes
// a connect-only code: no target, the engine's key, the password in
// .secret and nowhere else, and only the connect link handed over.
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

	password := secretOf(t, cfg)
	requireVerifierOf(t, r.payload.Agent.Verifier, password)
	requireNoSecret(t, r, cfg, password)
	require.NoFileExists(t, r.credFile, "no address, so no credential file")
	s := r.cfg.Agents[0].Setup
	require.True(t, s.AwaitingAddress)
	require.False(t, s.Refused)
	require.Contains(t, r.cfg.Agents[0].InitArgs, "--"+flagAllTables+"=true")

	// The link, the fingerprint, no laptop command: the catalog's
	// connect-only steps of SETUP_NOT_RUN.
	require.Equal(t, links.Portal+"/connect#"+r.res.Code, r.res.ConnectURL)
	require.Equal(t, []mcp.Link{{Label: agent.LabelConnect, URL: r.res.ConnectURL}}, r.res.Links)
	pm := r.res.PersonMessage
	require.Contains(t, pm, r.res.Fingerprint)
	require.Contains(t, pm, "connection string")
	require.NotContains(t, pm, "--setup-code")
	require.NoError(t, agent.CheckPersonMessage(pm), pm)
	mcptest.Require(t, pm, r.res.Links)
	catalog, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	v, ok := catalog.ConnectOnlyEntry(mcpcontract.VariantProblem, "SETUP_NOT_RUN", "", "")
	require.True(t, ok)
	got := make([]mcpcontract.StepKind, 0, len(r.res.NextSteps))
	for _, st := range r.res.NextSteps {
		got = append(got, mcpcontract.StepKind{Actor: st.Actor, Action: st.Action})
		require.NotContains(t, st.Command, "--setup-code")
	}
	require.Equal(t, v.Steps, got, "P OPEN_LINK, A END_TURN, A CALL_TOOL status")
	require.Equal(t, r.res.ConnectURL, r.res.NextSteps[0].URL)
	require.Equal(t, toolStatus, r.res.NextSteps[2].Tool)

	// Text: the link and the fingerprint, no laptop command.
	txt := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, connectOnlyArgs...)...)
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "\n\n"+r.res.ConnectURL+"\n\n")
	require.Contains(t, txt.stdout, "Setup fingerprint: "+r.res.Fingerprint+"\n")
	require.NotContains(t, txt.stdout, "--setup-code")
}

// While the code waits and has not expired, the same request prints it
// again; a change of tables or --new-code is refused with nothing changed,
// so .secret is never replaced while its code may already have run.
func TestInitRemoteConnectOnlyWhileWaiting(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	first := remote(t, cfg, connectOnlyArgs...)
	password := secretOf(t, cfg)

	again := remote(t, cfg, connectOnlyArgs...)
	require.True(t, again.res.Reused)
	require.Equal(t, first.res.Code, again.res.Code)
	require.True(t, again.res.ConnectOnly)

	for name, args := range map[string][]string{
		"other tables": {"--agent", "bot", "--write", "public.leads", "--operated-by", "agent"},
		"--new-code":   append(append([]string{}, connectOnlyArgs...), "--new-code"),
	} {
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, args...)...)
		require.Equal(t, exitError, r.code, name)
		require.Contains(t, r.stderr, "finish the pending setup on the connect page first, or wait until it expires at ", name)
	}
	require.Equal(t, password, secretOf(t, cfg), "nothing changed")
	c, err := config.Load(cfg)
	require.NoError(t, err)
	require.Equal(t, first.res.SetupID, c.Agents[0].Setup.SetupID)
}

// After the code expired, after the person refused the database, after
// --forget or with .secret gone, the next code is a recovery code: AGENT,
// a new password and its verifier, still connect-only.
func TestInitRemoteConnectOnlyRecoveryCodes(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		edit  func(t *testing.T, cfg string)
		extra []string
	}{
		"expired": {edit: func(t *testing.T, cfg string) {
			t.Helper()
			editSetup(t, cfg, func(s *config.Setup) { s.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
		}},
		"refused": {edit: func(t *testing.T, cfg string) {
			t.Helper()
			editSetup(t, cfg, func(s *config.Setup) { s.AwaitingAddress, s.Refused = false, true })
		}},
		"forget":      {extra: []string{"--forget"}},
		"secret gone": {edit: func(t *testing.T, cfg string) { t.Helper(); require.NoError(t, os.Remove(secretPathOf(cfg))) }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := connectOnlyConfig(t)
			first := remote(t, cfg, connectOnlyArgs...)
			old := secretOf(t, cfg)
			if tc.edit != nil {
				tc.edit(t, cfg)
			}
			args := connectOnlyArgs
			if tc.extra != nil {
				// --forget keeps the tables the agent's saved flags ask for.
				args = append([]string{"--agent", "bot", "--operated-by", "agent"}, tc.extra...)
			}
			again := remote(t, cfg, args...)
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
			require.NotContains(t, again.cfg.Agents[0].InitArgs, "--forget", "one-shot, never saved")
		})
	}
}

// --forget is refused, with nothing changed, without a pending connect-only
// setup or with a credential file.
func TestInitRemoteForgetRefused(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--forget", "--operated-by", "agent")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "there is no pending setup from the connect page to forget for bot")
	require.NoFileExists(t, cfg)

	withURL := tempConfig(t)
	remote(t, withURL, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	r = cliNoDB(t, "init", "--remote", "--config", withURL, "--agent", "bot", "--forget")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "there is no pending setup from the connect page to forget for bot")
}

// A run with --database-url drops a waiting connect-only code's .secret and
// goes on as a first run with that address.
func TestInitRemoteDatabaseURLReplacesAConnectOnlyCode(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	remote(t, cfg, connectOnlyArgs...)
	require.FileExists(t, secretPathOf(cfg))

	r := remote(t, cfg, "--agent", "bot", "--all-tables", "--operated-by", "agent", "--database-url", supabaseURL)
	require.False(t, r.res.ConnectOnly)
	require.NotNil(t, r.payload.Target)
	require.NotNil(t, r.payload.Agent.AllTables, "--all-tables with an address keeps allTables")
	require.Equal(t, string(setupcode.KindInstall), r.res.Kind)
	require.NoFileExists(t, secretPathOf(cfg))
	require.FileExists(t, r.credFile)
	require.False(t, r.cfg.Agents[0].Setup.AwaitingAddress)
	requireVerifierOf(t, r.payload.Agent.Verifier, credentialPassword(t, r.credFile))
}

// Without the connect path's conditions --database-url stays required,
// and the message names them; the flags' own usage errors come first.
func TestInitRemoteConnectOnlyUsage(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]string{
		"person-operated":            {"--agent", "bot", "--all-tables"},
		"vault off":                  {"--agent", "bot", "--all-tables", "--operated-by", "agent", "--vault", "off"},
		"all tables next to write":   {"--agent", "bot", "--all-tables", "--write", "public.leads", "--operated-by", "agent"},
		"forget with a database url": {"--agent", "bot", "--forget", "--database-url", supabaseURL},
	} {
		cfg := connectOnlyConfig(t)
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, args...)...)
		require.Equal(t, exitUsage, r.code, "%s: %s", name, r.stderr)
		require.NoFileExists(t, cfg, name)
	}
	cfg := connectOnlyConfig(t)
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--all-tables")
	require.Contains(t, r.stderr, "--database-url is required on the agent's first run")
	require.Contains(t, r.stderr, "makes a code for the connect page, which needs an agent-operated engine")
}

// A connect-only code needs the engine's key: without it init refuses,
// nothing written.
func TestInitRemoteConnectOnlyNeedsTheEngineKey(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	state := filepath.Join(filepath.Dir(cfg), stateDirName)
	require.NoError(t, os.MkdirAll(state, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(state, channel.KeyFileName), []byte("not a key"), 0o600))

	r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, connectOnlyArgs...)...)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "a setup code for the connect page needs the engine's key, and basalt cannot read or make it as this user")
	require.Contains(t, r.stderr, "or give --database-url <the database, without password>")
	require.NoFileExists(t, cfg)
	require.NoFileExists(t, secretPathOf(cfg))
}

// --forget as the contract spells it, with only --agent: the recovery code
// asks for what the saved flags ask for (tables, prefix, timeout) on the
// agent-operated engine they name.
func TestInitRemoteForgetKeepsTheSavedRequest(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	first := remote(t, cfg, "--agent", "bot", "--all-tables", "--operated-by", "agent", "--prefix", "acme", "--statement-timeout", "45s")
	again := remote(t, cfg, "--agent", "bot", "--forget")
	require.NotEqual(t, first.res.SetupID, again.res.SetupID)
	require.Equal(t, string(setupcode.KindAgent), again.res.Kind)
	require.Equal(t, "acme", again.payload.Prefix)
	require.Equal(t, int64(45000), again.payload.Agent.StatementTimeoutMs)
	require.NotNil(t, again.payload.Agent.AllTables)
	require.Equal(t, mcpcontract.OperatedByAgent, again.cfg.OperatedBy)
	require.Equal(t, first.cfg.Agents[0].InitArgs, again.cfg.Agents[0].InitArgs)
}

// A connect link over the engine's linkBudget is left out: the message
// names the connect page without a URL, and the step opens it.
func TestInitRemoteConnectOnlyOverTheBudget(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	remote(t, cfg, connectOnlyArgs...)
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["linkBudget"] = 100
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg, raw, 0o600))

	r := remote(t, cfg, connectOnlyArgs...)
	require.True(t, r.res.ConnectOnly)
	require.Empty(t, r.res.ConnectURL)
	require.Empty(t, r.res.Links)
	require.NotContains(t, r.res.PersonMessage, "https://")
	require.Contains(t, r.res.PersonMessage, "portal.basaltvault.app/connect")
	require.NoError(t, agent.CheckPersonMessage(r.res.PersonMessage), r.res.PersonMessage)
	mcptest.Require(t, r.res.PersonMessage, r.res.Links)
	require.Equal(t, "OPEN_LINK", r.res.NextSteps[0].Action)
	require.Equal(t, links.Portal+links.ConnectPath, r.res.NextSteps[0].URL)

	txt := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, connectOnlyArgs...)...)
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "\n\n"+r.res.Code+"\n\n")
	require.NotContains(t, txt.stdout, "--setup-code")
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
	run := func(t *testing.T, args ...string) result {
		t.Helper()
		var stdout, stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
		c.agentLogin = refusedLogin
		c.probe = noNetworkProbe
		c.host = newFakeHost(t)
		code := runInitAdmin(c, takePathFlags(c, runInit, args[1:]))
		return result{code, stdout.String(), stderr.String()}
	}
	r := remoteWith(t, run, cfg, connectOnlyArgs...)
	require.True(t, r.res.ConnectOnly)
	require.NotNil(t, r.payload.Engine)
	requireVerifierOf(t, r.payload.Agent.Verifier, secretOf(t, cfg))
	require.FileExists(t, filepath.Join(filepath.Dir(cfg), stateDirName, channel.KeyFileName))

	again := remoteWith(t, run, cfg, "--agent", "bot", "--forget")
	require.NotEqual(t, r.res.SetupID, again.res.SetupID)
	requireVerifierOf(t, again.payload.Agent.Verifier, secretOf(t, cfg))
}

// basalt status on an agent whose connect-only setup waits reads no
// credential and no database: it reports the setup from engine.json, with
// the connect link, and after a NO the refusal.
func TestStatusOfAWaitingConnectOnlyAgent(t *testing.T) {
	t.Parallel()
	cfg := connectOnlyConfig(t)
	r := remote(t, cfg, connectOnlyArgs...)
	_, service := connecttest.Start(t)
	status := func() map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
		c.handoff.ServiceURL = service // a connect service that holds nothing
		code := runStatus(c, []string{"--agent", "bot", "--config", cfg, "--json"})
		require.Equal(t, exitOK, code, stderr.String())
		var out map[string]any
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &out), stdout.String())
		return out
	}
	out := status()
	setup := out["setup"].(map[string]any)
	require.Equal(t, "PENDING", setup["state"])
	require.Equal(t, true, setup["connectOnly"])
	require.Contains(t, fmtJSON(t, out), r.res.ConnectURL)
	require.Contains(t, fmtJSON(t, out), "SETUP_NOT_RUN")

	editSetup(t, cfg, func(s *config.Setup) { s.AwaitingAddress, s.Refused = false, true })
	out = status()
	require.Equal(t, "REFUSED", out["setup"].(map[string]any)["state"])
	require.Contains(t, fmtJSON(t, out), "DATABASE_REFUSED")
}

func fmtJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}
