package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

const (
	supabaseURL = "postgresql://postgres.abcdefghijklmnopqrst@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
	supabaseRef = "abcdefghijklmnopqrst"
	// adminSecret is the admin password the tests' environment holds:
	// basalt init --remote ignores it.
	adminSecret = "adminsecret"
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{4}( [0-9a-f]{4}){4}$`)

// remoteRun is one basalt init --remote with its files.
type remoteRun struct {
	result
	res      setup.RemoteInitResult
	payload  setupcode.Payload
	cfg      config.Config
	credFile string
}

// remoteEnv is how a test runs basalt init --remote: the host, the
// environment beside the admin URL every run sees (and ignores), the
// agent's login and the TLS probe of a new credential. A nil login or
// probe is the real one.
type remoteEnv struct {
	host      *fakeHost
	env       map[string]string
	login     func(context.Context, string) (cli.AgentConn, error)
	probe     func(context.Context, string) error
	noNetwork bool
	// prefix is the role prefix of a first code (cli.IO.RolePrefix).
	prefix string
}

// noDB is a run as root (the system socket directory keeps socket paths
// short) where every agent login is refused and no host is dialed.
func noDB(t *testing.T) remoteEnv {
	t.Helper()
	return remoteEnv{host: systemSocketHost(t), login: refusedLogin, probe: noNetworkProbe, noNetwork: true}
}

// withDB is a run as root against a real database.
func withDB(t *testing.T) remoteEnv {
	t.Helper()
	return remoteEnv{host: systemSocketHost(t)}
}

// io is the cli.IO of a run in e, writing to stdout and stderr.
func (e remoteEnv) io(stdout, stderr *bytes.Buffer) *cli.IO {
	c := newIO(context.Background(), cli.Stdio{In: strings.NewReader(""), Out: stdout, Err: stderr},
		func(k string) string {
			if k == setup.EnvAdminURL {
				return "postgres://admin:" + adminSecret + "@db.example.com/postgres"
			}
			return e.env[k]
		})
	c.Host = e.host
	c.RolePrefix = e.prefix
	if e.login != nil {
		c.AgentLogin = e.login
	}
	if e.probe != nil {
		c.Probe = e.probe
	}
	if e.noNetwork {
		c.FetchChain = nil
	}
	return c
}

// cli runs basalt init with args (after "init") in e: --remote as the
// binary does, else the admin setup the tests of other commands still use.
func (e remoteEnv) cli(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := e.io(&stdout, &stderr)
	code := runInit(c, SetupHost{}, takePathFlags(c, runInit, args))
	return result{code, stdout.String(), stderr.String()}
}

// refusedLogin stands in for a database that refuses the agent's login
// (its role does not exist, or has another password), so tests without
// Postgres reach no network.
func refusedLogin(context.Context, string) (cli.AgentConn, error) {
	return nil, handoff.ErrLoginRefused
}

// noNetworkProbe stands in for the TLS probe of a new credential
// (setup.HardenedCredential): a database that cannot be reached, so tests without
// Postgres never dial the example hosts (Supabase's pooler among them).
func noNetworkProbe(context.Context, string) error { return context.DeadlineExceeded }

// cliNoDB runs basalt init with every agent login refused.
func cliNoDB(t *testing.T, args ...string) result {
	t.Helper()
	return noDB(t).cli(t, args[1:]...)
}

// remote runs basalt init --remote with the engine config at cfg, with
// every agent login refused.
func remote(t *testing.T, cfg string, args ...string) remoteRun {
	t.Helper()
	return remoteWith(t, noDB(t), cfg, args...)
}

// remoteDBRun is remote against a real database.
func remoteDBRun(t *testing.T, cfg string, args ...string) remoteRun {
	t.Helper()
	return remoteWith(t, withDB(t), cfg, args...)
}

// remoteWith runs basalt init --remote in e with the config at cfg (none
// given when cfg is ""), requires it to succeed, and reads what it wrote.
func remoteWith(t *testing.T, e remoteEnv, cfg string, args ...string) remoteRun {
	t.Helper()
	all := []string{"--remote"}
	if cfg != "" {
		all = append(all, "--config", cfg)
	}
	all = append(all, args...)
	var stdout, stderr bytes.Buffer
	c := e.io(&stdout, &stderr)
	res, err := setupcli.InitRemote(c, SetupHost{}, takePathFlags(c, runInit, all))
	require.NoError(t, err, stderr.String())
	require.NoError(t, setupcli.PrintRemoteResult(c, res))
	r := remoteRun{result: result{cli.ExitOK, stdout.String(), stderr.String()}, res: res}
	p, err := setupcode.Decode(r.res.Code)
	require.NoError(t, err)
	r.payload = p
	if cfg == "" {
		return r
	}
	r.cfg, err = config.Load(cfg)
	require.NoError(t, err)
	for _, a := range r.cfg.Agents {
		if a.Name == res.Agent {
			r.credFile = a.Store.CredentialFile
		}
	}
	return r
}

// withState makes the state directory next to cfg: the tests' host runs
// init as root, which never makes it, and a connect-only code needs the
// engine's key there.
func withState(t *testing.T, cfg string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(filepath.Dir(cfg), setup.StateDirName), 0o700))
	return cfg
}

// agentDSN is the agent's connection string for the database base (without
// a password) with password pw.
func agentDSN(t *testing.T, base, prefix, name, pw string) string {
	t.Helper()
	role, err := guardmodel.Names{Prefix: prefix}.Agent(name)
	require.NoError(t, err)
	dsn, err := guard.AgentConnString(base, role, pw)
	require.NoError(t, err)
	return dsn
}

// seedCredential leaves cfg as the engine does once the person confirmed
// a connect-only setup's database: basalt init --remote made the code, the
// agent's credential file holds dsn, .secret is gone and the pending setup
// no longer waits for an address. The role's prefix is dsn's user's.
func seedCredential(t *testing.T, e remoteEnv, cfg, name, dsn string) remoteRun {
	t.Helper()
	withState(t, cfg)
	first := remoteWith(t, e, cfg, "--agent", name)
	require.NoError(t, config.WriteFile(first.credFile, []byte(dsn+"\n")))
	require.NoError(t, os.Remove(config.SecretPath(first.credFile, name)))
	editConfig(t, cfg, func(c *config.Config) {
		a := &c.Agents[0]
		a.Setup.AwaitingAddress = false
	})
	return first
}

// installedAgent is seedCredential for the bot once the engine saw the
// setup recorded: the agent has its credential and no pending setup.
func installedAgent(t *testing.T, e remoteEnv, cfg, dsn string) {
	t.Helper()
	seedCredential(t, e, cfg, "bot", dsn)
	clearSetup(t, cfg)
}

// editConfig changes engine.json at cfg.
func editConfig(t *testing.T, cfg string, edit func(c *config.Config)) {
	t.Helper()
	c, err := config.Load(cfg)
	require.NoError(t, err)
	edit(&c)
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
}

// clearSetup drops the pending setup from engine.json, as the engine does
// when it finds the setup recorded.
func clearSetup(t *testing.T, cfg string) {
	t.Helper()
	editConfig(t, cfg, func(c *config.Config) { c.Agents[0].Setup = nil })
}

// botPassword is the password of the bot's credential in the tests.
const botPassword = "0123abcd"

// supabaseDSN is the bot's credential through Supabase's pooler.
func supabaseDSN(t *testing.T) string {
	t.Helper()
	return agentDSN(t, supabaseURL, guardmodel.DefaultPrefix, "bot", botPassword)
}

// credentialPassword reads the agent's password from a credential file and
// checks its mode.
func credentialPassword(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), fi.Mode().Perm(), path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	pw, ok := u.User.Password()
	require.True(t, ok)
	return pw
}

// requireNoSecret checks a run printed and saved nothing of the password.
func requireNoSecret(t *testing.T, r remoteRun, cfgPath, password string) {
	t.Helper()
	require.NotEmpty(t, password)
	require.NotContains(t, r.stdout, password)
	require.NotContains(t, r.stderr, password)
	require.NotContains(t, r.res.Code, password)
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), password)
	require.NotContains(t, string(raw), adminSecret)
	require.NotContains(t, r.stdout+r.stderr, adminSecret, "BASALT_ADMIN_DATABASE_URL is ignored")
}

// requireVerifierOf checks verifier is the SCRAM verifier of password.
func requireVerifierOf(t *testing.T, verifier, password string) {
	t.Helper()
	m := regexp.MustCompile(`^SCRAM-SHA-256\$4096:([^$]+)\$`).FindStringSubmatch(verifier)
	require.NotNil(t, m)
	salt, err := base64.StdEncoding.DecodeString(m[1])
	require.NoError(t, err)
	want, err := setupcode.VerifierWithSalt(password, salt)
	require.NoError(t, err)
	require.Equal(t, want, verifier)
}

// basalt init --remote takes --agent and nothing else: every flag the CLI
// cut removed is a usage error, with nothing written.
func TestInitRemoteUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--agent", "bot", "--write", "public.leads"},
		{"--agent", "bot", "--read", "public.leads"},
		{"--agent", "bot", "--all-tables"},
		{"--agent", "bot", "--database-url", supabaseURL},
		{"--agent", "bot", "--new-code"},
		{"--agent", "bot", "--forget"},
		{"--agent", "bot", "--json"},
		{"--agent", "bot", "--yes"},
		{"--agent", "bot", "--operated-by", "agent"},
		{"--agent", "bot", "--vault", "off"},
		{"--agent", "bot", "--trust-root", "ab"},
		{"--agent", "bot", "--prefix", "acme"},
		{"--agent", "bot", "--statement-timeout", "5s"},
		{"--agent", "bot", "--demo"},
		{"--agent", "bot", "extra"},
		{"--agent", "Bad-Name"},
	} {
		cfg := withState(t, tempConfig(t))
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, args...)...)
		require.Equal(t, cli.ExitUsage, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, r.stdout)
		require.NoFileExists(t, cfg, "%v", args)
	}
}

// Without --agent, init --remote sets up the config's one agent, or the
// default name on a new engine; with more than one agent it asks for
// --agent.
func TestInitRemoteWithoutAgent(t *testing.T) {
	t.Parallel()
	cfg := withState(t, tempConfig(t))
	first := remote(t, cfg)
	require.Equal(t, "demo_bot", first.res.Agent)
	again := remote(t, cfg)
	require.True(t, again.res.Reused)
	require.Equal(t, first.res.SetupID, again.res.SetupID)

	remote(t, cfg, "--agent", "lead_bot")
	r := cliNoDB(t, "init", "--remote", "--config", cfg)
	require.Equal(t, cli.ExitUsage, r.code, r.stderr)
	require.Contains(t, r.stderr, "more than one agent: give --agent NAME")
}

// An agent with a credential gets a code with the credential's database as
// its target: here the role does not log in while the confirmed
// connect-only setup is pending, so the run makes a fresh INSTALL code with
// the password the credential holds.
func TestInitRemoteMakesATargetCode(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	seed := seedCredential(t, noDB(t), cfg, "lead_bot", agentDSN(t, supabaseURL, guardmodel.DefaultPrefix, "lead_bot", "0123abcd"))
	r := remote(t, cfg, "--agent", "lead_bot")

	p := r.payload
	require.NotEqual(t, seed.res.SetupID, p.SetupID, "a fresh code")
	require.Equal(t, setupcode.KindInstall, p.Kind)
	require.Equal(t, &setupcode.Target{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: supabaseRef}, p.Target)
	require.Equal(t, setupcode.Guard{From: 0, To: guard.LatestVersion()}, p.Guard)
	require.Equal(t, &setupcode.AllTables{Schemas: []string{"public"}}, p.Agent.AllTables, "the person ticks the tables")
	require.Nil(t, p.Agent.Write)
	require.Nil(t, p.Agent.Read)
	require.Equal(t, guardmodel.DefaultStatementTimeout.Milliseconds(), p.Agent.StatementTimeoutMs)
	requireVerifierOf(t, p.Agent.Verifier, "0123abcd")
	require.Equal(t, "0123abcd", credentialPassword(t, r.credFile), "the credential stays")
	requireNoSecret(t, r, cfg, "0123abcd")
	created, err := p.CreatedAt()
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), created, time.Minute)
	require.Equal(t, created.Add(setupcode.Lifetime).Truncate(time.Second).Format(time.RFC3339), p.ExpiresAt)

	// The result.
	require.Equal(t, "lead_bot", r.res.Agent)
	require.Equal(t, p.SetupID, r.res.SetupID)
	require.Equal(t, "INSTALL", r.res.Kind)
	require.False(t, r.res.Reused)
	require.Equal(t, p.ExpiresAt, r.res.ExpiresAt)
	require.Equal(t, p.Fingerprint(), r.res.Fingerprint)
	require.Regexp(t, fingerprintPattern, r.res.Fingerprint)
	requireConnectGuidance(t, r.res)

	// engine.json: operatedBy, the portal and the pending setup, no secret.
	require.Equal(t, "AGENT", r.cfg.OperatedBy)
	require.Equal(t, links.Portal, r.cfg.PagesURL)
	a := r.cfg.Agents[0]
	require.Equal(t, filepath.Join(filepath.Dir(cfg), "agents", "lead_bot.url"), a.Store.CredentialFile)
	require.Equal(t, &config.Setup{
		SetupID: p.SetupID, Kind: "INSTALL", GuardVersion: guard.LatestVersion(),
		ExpiresAt: p.ExpiresAt, Code: r.res.Code, Fingerprint: r.res.Fingerprint,
	}, a.Setup)
	_, err = NewCommands(a.Name, cfg, "linux", AgentServiceManager())
	require.NoError(t, err, "the agent's entry is one the engine accepts")
	pages, err := r.cfg.Pages()
	require.NoError(t, err)
	require.Empty(t, pages.Addr, "the engine serves no local pages for the portal")

	// Text output: the code on a line of its own, the link and the
	// fingerprint.
	require.Contains(t, r.stdout, "\n\n"+r.res.Code+"\n\n")
	require.Contains(t, r.stdout, "Setup fingerprint: "+r.res.Fingerprint+"\n")
	require.Contains(t, r.stdout, "\n\n"+r.res.ConnectURL+"\n\n")
	require.Contains(t, r.stdout, "  "+cli.ShellJoin(r.res.MCPCommand)+"\n")
}

// requireConnectGuidance checks a result that carries the connect link: the
// link is the code in the portal's fragment, on a line of its own in the
// message, and the person runs no command.
func requireConnectGuidance(t *testing.T, res setup.RemoteInitResult) {
	t.Helper()
	require.GreaterOrEqual(t, len(res.MCPCommand), 4)
	require.Equal(t, []string{fakeBin, "mcp", "--agent", res.Agent}, res.MCPCommand[:4])
	require.Equal(t, links.Portal+"/connect#"+res.Code, res.ConnectURL)
	pm := res.PersonMessage
	require.Contains(t, pm, res.Fingerprint)
	require.Contains(t, pm, "\n\n"+res.ConnectURL+"\n\n", "the link stands on a line of its own")
	require.Contains(t, pm, "Basalt Vault, a hosted service")
	require.NotContains(t, pm, "basalt init", "the person runs no command")
	mcptest.Require(t, pm, []toolresult.Link{{Label: guidance.LabelConnect, URL: res.ConnectURL}})
}

// An agent-operated engine with the Vault on hands the connect link; an
// engine whose config another init made person-operated, or turned the
// Vault off, hands where to paste the code instead. There is no network call: the link only holds the
// code.
func TestInitRemoteHandsTheConnectLinkOnlyWithTheVaultOn(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		edit func(c *config.Config)
		link bool
	}{
		"agent-operated, vault on":  {nil, true},
		"agent-operated, vault off": {func(c *config.Config) { c.Vault = config.VaultOff }, false},
		"person-operated":           {func(c *config.Config) { c.OperatedBy = "PERSON"; c.Vault = "" }, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := tempConfig(t)
			installedAgent(t, noDB(t), cfg, supabaseDSN(t))
			if tc.edit != nil {
				editConfig(t, cfg, tc.edit)
			}
			r := remote(t, cfg, "--agent", "bot")
			require.Equal(t, "AGENT", r.res.Kind, "the database refuses the credential: a new password")
			if tc.link {
				requireConnectGuidance(t, r.res)
				return
			}
			require.Empty(t, r.res.ConnectURL, "no link, no laptop command: the code is pasted at the connect page")
			require.NotContains(t, r.res.PersonMessage, "--setup-code")
			require.Contains(t, r.res.PersonMessage, "portal.basaltvault.app/connect")
			require.LessOrEqual(t, utf8.RuneCountInString(r.res.PersonMessage), guidance.MaxPersonMessageLength)
		})
	}
}

// A link over the engine's linkBudget is not printed: the code is, with the
// address to paste it at.
func TestInitRemoteSaysWhereToPasteTheCodeWhenTheLinkIsOverTheBudget(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	first := remote(t, cfg, "--agent", "bot")
	require.NotEmpty(t, first.res.ConnectURL)
	editConfig(t, cfg, func(c *config.Config) { b := len(first.res.ConnectURL) - 1; c.LinkBudget = &b })

	again := remote(t, cfg, "--agent", "bot")
	require.Equal(t, first.res.Code, again.res.Code, "the pending code is printed again")
	require.Empty(t, again.res.ConnectURL)
	require.NotContains(t, again.stdout, "/connect#")
	require.Contains(t, again.stdout, "\n\n"+first.res.Code+"\n\n")
	require.Contains(t, again.stdout, "paste the setup code at portal.basaltvault.app/connect.")
}

func TestConnectMessageFitsForTheLongestName(t *testing.T) {
	t.Parallel()
	name := ""
	for n := 1; n < 100; n++ {
		if candidate := strings.Repeat("a", n); config.ValidAgentName(candidate) {
			name = candidate
		}
	}
	pm, ls := guidance.ConnectMessage("Finish setting up Basalt for "+name+".", links.Portal+"/connect#basalt-setup.1.x.y", "3f9a 21c0 7d44 e1b2 90ac")
	require.NoError(t, guidance.CheckPersonMessage(pm), pm)
	mcptest.Require(t, pm, ls)
}

// A new credential keeps the strongest TLS protection the probe confirms,
// and init says which in one line: through Supabase's pooler, which
// answers before any SASL message, a verified certificate without channel
// binding.
func TestInitRemoteHardensTheCredentialThroughThePooler(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	var probed []string
	e := noDB(t)
	e.probe = func(_ context.Context, dsn string) error {
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		probed = append(probed, u.Query().Get("sslmode")+"/"+u.Query().Get("channel_binding"))
		return &pgconn.PgError{Code: setup.SQLStateInternal, Message: setup.SupavisorNoTenant}
	}
	r := remoteWith(t, e, cfg, "--agent", "bot")
	require.Equal(t, []string{"verify-full/require", "verify-full/"}, probed)
	pending := r.credFile + setup.PendingSuffix
	raw, err := os.ReadFile(pending)
	require.NoError(t, err)
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	require.Equal(t, "verify-full", u.Query().Get("sslmode"))
	require.Empty(t, u.Query().Get("channel_binding"))
	const line = "basalt: connection protected: database identity verified (channel binding not available through the Supabase pooler)\n"
	require.Equal(t, 1, strings.Count(r.stderr, line), r.stderr)
	requireNoSecret(t, r, cfg, credentialPassword(t, pending))
}

// basalt init keeps host, port and dbname parameters in the credential it
// writes; --remote can't target such a URL. It says so and leaves the file,
// the running engine's credential, as it is.
func TestInitRemoteExplainsACredentialWithTargetParams(t *testing.T) {
	t.Parallel()
	const stored = "postgres://basalt_agent_bot:enginepw@db.example.com:5432/crm?sslmode=require&host=10.0.0.9\n"
	for _, suffix := range []string{"", setup.PendingSuffix} {
		cfg := tempConfig(t)
		path := filepath.Join(filepath.Dir(cfg), "agents", "bot.url"+suffix)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(stored), config.FileMode))

		r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")

		require.Equal(t, cli.ExitError, r.code, "%q: %s", suffix, r.stderr)
		require.Contains(t, r.stderr, "was written by basalt init for a connection string with a host= parameter")
		require.Contains(t, r.stderr, "Use another --agent name")
		require.NotContains(t, r.stderr, "enginepw")
		require.Empty(t, r.stdout)
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, stored, string(raw), "the credential is not overwritten")
		require.NoFileExists(t, cfg)
	}
}

// The database refuses the agent's credential (CREDENTIAL_REJECTED): with
// no flag, the run makes an AGENT code with a new password, kept in
// .pending (the refusal could have been transient, so the credential file
// stays). A re-run while it is pending prints it again.
func TestInitRemoteRejectedCredentialGetsANewPassword(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))

	rotate := remote(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.False(t, rotate.res.Reused)
	require.Equal(t, "0123abcd", credentialPassword(t, rotate.credFile))
	pw := credentialPassword(t, rotate.credFile+setup.PendingSuffix)
	require.NotEqual(t, "0123abcd", pw)
	requireVerifierOf(t, rotate.payload.Agent.Verifier, pw)
	requireNoSecret(t, rotate, cfg, pw)

	again := remote(t, cfg, "--agent", "bot")
	require.True(t, again.res.Reused)
	require.Contains(t, again.stderr, "a setup code is pending for this agent; here it is again")
	require.Equal(t, rotate.res.SetupID, again.res.SetupID)
	require.Equal(t, rotate.res.ExpiresAt, again.res.ExpiresAt)
	require.Equal(t, rotate.res.Code, again.res.Code)
	require.Equal(t, pw, credentialPassword(t, rotate.credFile+setup.PendingSuffix))
}

// An expired code (SETUP_EXPIRED) is never printed again: the next run
// makes a fresh one.
func TestInitRemoteReplacesAnExpiredCode(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	first := remote(t, cfg, "--agent", "bot")
	editConfig(t, cfg, func(c *config.Config) {
		c.Agents[0].Setup.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	})

	again := remote(t, cfg, "--agent", "bot")
	require.False(t, again.res.Reused)
	require.NotEqual(t, first.res.SetupID, again.res.SetupID)
	require.NotEqual(t, first.res.Code, again.res.Code)
	require.NotEqual(t, first.res.Fingerprint, again.res.Fingerprint)
	require.NotContains(t, again.stdout+again.stderr, first.res.Code, "an expired code is never reprinted")
}

func TestInitRemoteRefusesASymlinkedCredential(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := seedCredential(t, noDB(t), cfg, "bot", supabaseDSN(t))
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte("postgres://x@h/db\n"), 0o600))
	require.NoError(t, os.Remove(first.credFile))
	require.NoError(t, os.Symlink(target, first.credFile))

	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "is not usable")
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "postgres://x@h/db\n", string(raw), "the link's target is untouched")

	// A .pending planted as a link is refused the same way.
	require.NoError(t, os.Remove(first.credFile))
	require.NoError(t, config.WriteFile(first.credFile, []byte(supabaseDSN(t)+"\n")))
	require.NoError(t, os.Symlink(target, first.credFile+setup.PendingSuffix))
	r = cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, setup.PendingSuffix+" is not usable")

	// config.WriteFile, which writes every file init writes, refuses a link.
	require.Error(t, config.WriteFile(first.credFile+setup.PendingSuffix, []byte("x")))
	raw, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "postgres://x@h/db\n", string(raw))
}

// remoteDB is a database for --remote runs: its URL without the password.
func remoteDB(t *testing.T) (*guardtest.DB, string) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	u.User = url.User(u.User.Username())
	return d, u.String()
}

// seedDB is seedCredential for the bot in database d: the credential, for
// the role of d's prefix, with password pw.
func seedDB(t *testing.T, e remoteEnv, cfg string, d *guardtest.DB, dbURL, pw string) {
	t.Helper()
	seedCredential(t, e, cfg, "bot", agentDSN(t, dbURL, d.Names.Prefix, "bot", pw))
}

// runCode does what the connect page does with an INSTALL or AGENT code:
// the role from the verifier, the grants and record_setup, in one
// transaction as the admin. With agent.allTables the person ticks
// public.leads; an AGENT code that names no tables keeps the grants.
func runCode(t *testing.T, d *guardtest.DB, p setupcode.Payload) {
	t.Helper()
	ctx := context.Background()
	spec := guardmodel.AgentSpec{}
	agentName := ""
	if p.Agent != nil {
		agentName = p.Agent.Name
		spec = guardmodel.AgentSpec{
			Name: p.Agent.Name, Write: p.Agent.Write, Read: p.Agent.Read,
			Verifier: p.Agent.Verifier, CreateOnly: p.Kind == setupcode.KindInstall,
			StatementTimeout: time.Duration(p.Agent.StatementTimeoutMs) * time.Millisecond,
		}
		if p.Agent.AllTables != nil {
			spec.Write = []string{"public.leads"}
		}
	}
	expires, err := p.ExpiresTime()
	require.NoError(t, err)
	id, err := uuid.Parse(p.SetupID)
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error {
		if p.Agent != nil {
			s, err := guard.PlanInit(ctx, tx, guardmodel.InitOptions{Names: d.Names, Agent: spec})
			if err != nil {
				return err
			}
			if err := guard.ApplyScript(ctx, tx, s); err != nil {
				return err
			}
		}
		_, err := guard.RecordSetup(ctx, tx, d.Names, guardmodel.Setup{
			ID: id, Kind: string(p.Kind), Agent: agentName,
			GuardVersion: p.Guard.To, ExpiresAt: expires,
		})
		return err
	}))
}

func TestInitRemoteAgainstTheDatabase(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	seedDB(t, withDB(t), cfg, d, dbURL, "0123abcd")

	// The role does not log in yet while the confirmed setup is pending:
	// INSTALL, run by the person; the bot's password now logs in.
	install := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "INSTALL", install.res.Kind)
	requireVerifierOf(t, install.payload.Agent.Verifier, "0123abcd")
	runCode(t, d, install.payload)

	// The setup is recorded: a re-run makes a new code, an AGENT code with
	// no change and no verifier, since the guard is this build's.
	noChange := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", noChange.res.Kind)
	require.NotEqual(t, install.res.SetupID, noChange.res.SetupID)
	require.Empty(t, noChange.payload.Agent.Verifier)
	require.True(t, noChange.payload.KeepsGrants(), "it names no tables: the role keeps its grants")
	require.Equal(t, setupcode.Guard{From: guard.LatestVersion(), To: guard.LatestVersion()}, noChange.payload.Guard)
	require.Equal(t, "0123abcd", credentialPassword(t, install.credFile))

	// Pending and unchanged: the same code again.
	again := remoteDBRun(t, cfg, "--agent", "bot")
	require.True(t, again.res.Reused)
	require.Equal(t, noChange.res.SetupID, again.res.SetupID)

	// Someone else's password for the role: the database refuses the bot's
	// credential, so the next run makes an AGENT code with a new password,
	// in .pending until the person runs it.
	runCode(t, d, noChange.payload)
	clearSetup(t, cfg)
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	d.Exec(t, `ALTER ROLE `+pgx.Identifier{role}.Sanitize()+` PASSWORD 'not-the-bots'`)
	rotate := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.True(t, rotate.payload.KeepsGrants(), "a rejected password asks for no tables")
	require.Equal(t, "0123abcd", credentialPassword(t, install.credFile))
	pw2 := credentialPassword(t, install.credFile+setup.PendingSuffix)
	require.NotEqual(t, "0123abcd", pw2)
	requireVerifierOf(t, rotate.payload.Agent.Verifier, pw2)
	requireNoSecret(t, rotate, cfg, pw2)

	// The person runs it: the next run logs in with .pending and moves it
	// over the credential file.
	runCode(t, d, rotate.payload)
	after := remoteDBRun(t, cfg, "--agent", "bot")
	require.False(t, after.res.Reused)
	require.Equal(t, pw2, credentialPassword(t, install.credFile))
	require.NoFileExists(t, install.credFile+setup.PendingSuffix)

	// UPGRADE when the guard is older than the build: no agent part.
	runCode(t, d, after.payload)
	d.Exec(t, fmt.Sprintf(`DELETE FROM basalt_meta.schema_version WHERE version = %d`, guard.LatestVersion()))
	upgrade := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "UPGRADE", upgrade.res.Kind)
	require.Nil(t, upgrade.payload.Agent)
	require.Equal(t, setupcode.Guard{From: guard.LatestVersion() - 1, To: guard.LatestVersion()}, upgrade.payload.Guard)
	require.Equal(t, pw2, credentialPassword(t, install.credFile))
}

// The person confirmed a database of a server where the bot's role already
// logs in (the setup ran in another database there), and the database does
// not record the setup (SETUP_NOT_FOUND): with no flag, the next run makes
// an AGENT code with a new password for that database.
func TestInitRemoteSetupNotFoundGetsANewPassword(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	seedDB(t, withDB(t), cfg, d, dbURL, botPassword)
	salt := make([]byte, 16)
	verifier, err := setupcode.VerifierWithSalt(botPassword, salt)
	require.NoError(t, err)
	other, expires, err := setupcode.NewSetupID(time.Now(), rand.Reader)
	require.NoError(t, err)
	runCode(t, d, setupcode.Payload{
		SetupID: other, Kind: setupcode.KindInstall, ExpiresAt: expires, Guard: setupcode.Guard{To: guard.LatestVersion()},
		Agent: &setupcode.Agent{Name: "bot", Write: []string{"public.leads"}, Verifier: verifier},
	})
	pending, err := config.Load(cfg)
	require.NoError(t, err)

	r := remoteDBRun(t, cfg, "--agent", "bot")
	require.NotEqual(t, pending.Agents[0].Setup.SetupID, r.res.SetupID)
	require.Equal(t, "AGENT", r.res.Kind)
	require.NotNil(t, r.payload.Target)
	require.Equal(t, botPassword, credentialPassword(t, r.credFile))
	pw := credentialPassword(t, r.credFile+setup.PendingSuffix)
	require.NotEqual(t, botPassword, pw)
	requireVerifierOf(t, r.payload.Agent.Verifier, pw)
}

// After a connect-only INSTALL where the person ticked some tables, a
// re-run's AGENT code names no tables, never every table in public: the
// role keeps the grants it holds, and engine.json keeps no copy of them.
func TestInitRemoteAgentCodeKeepsTheGrants(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	seedCredential(t, withDB(t), cfg, "bot", agentDSN(t, dbURL, d.Names.Prefix, "bot", botPassword))
	pending, err := config.Load(cfg)
	require.NoError(t, err)
	verifier, err := setupcode.VerifierWithSalt(botPassword, make([]byte, 16))
	require.NoError(t, err)
	// What the connect page runs with the ticks: the setup the engine
	// waits for, granting only public.leads.
	runCode(t, d, setupcode.Payload{
		SetupID: pending.Agents[0].Setup.SetupID, Kind: setupcode.KindInstall, ExpiresAt: pending.Agents[0].Setup.ExpiresAt,
		Guard: setupcode.Guard{To: guard.LatestVersion()}, Agent: &setupcode.Agent{Name: "bot", Write: []string{"public.leads"}, Verifier: verifier},
	})
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	ident := pgx.Identifier{role}.Sanitize()

	r := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", r.res.Kind)
	require.Nil(t, r.payload.Agent.AllTables)
	require.Empty(t, r.payload.Agent.Write)
	require.Empty(t, r.payload.Agent.Read)
	require.True(t, r.payload.KeepsGrants())
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "initArgs", "engine.json saves no flags")
	require.NotContains(t, string(raw), "public.leads", "engine.json keeps no copy of the tables")

	again := remoteDBRun(t, cfg, "--agent", "bot")
	require.True(t, again.res.Reused, "the pending code is printed again")

	// The database rejects the bot's password: the re-run's AGENT code
	// rotates it and names no tables, and on the connect page the role
	// keeps exactly the table it had. Nothing is added.
	runViaConnect(t, d, r.res.Code)
	clearSetup(t, cfg)
	d.Exec(t, `ALTER ROLE `+ident+` PASSWORD 'not-the-bots'`)
	rotate := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.NotEmpty(t, rotate.payload.Agent.Verifier)
	require.True(t, rotate.payload.KeepsGrants())
	runViaConnect(t, d, rotate.res.Code)
	require.Equal(t, []string{"public.leads"}, grantedTables(t, d, role), "exactly the role's grants")

	// The role was dropped: the next code is the same kind of code, and on
	// the connect page it runs as an INSTALL with ticks.
	promoted := remoteDBRun(t, cfg, "--agent", "bot") // logs in with .pending, moves it over
	require.FileExists(t, promoted.credFile)
	runViaConnect(t, d, promoted.res.Code)
	clearSetup(t, cfg)
	d.Exec(t, `DROP OWNED BY `+ident+`; DROP ROLE `+ident)
	dropped := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", dropped.res.Kind)
	require.True(t, dropped.payload.KeepsGrants())
	runViaConnect(t, d, dropped.res.Code, "public.lead_notes")
	require.Equal(t, []string{"public.lead_notes"}, grantedTables(t, d, role), "only the ticked table")
}

// grantedTables are the tables role holds a privilege on, in name order.
func grantedTables(t *testing.T, d *guardtest.DB, role string) []string {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `SELECT DISTINCT c.oid::pg_catalog.regclass::text FROM pg_catalog.pg_class c,
		LATERAL pg_catalog.aclexplode(c.relacl) a WHERE a.grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1) AND c.relkind IN ('r', 'p', 'v')
		ORDER BY 1`, role)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	for i, name := range got {
		if !strings.Contains(name, ".") {
			got[i] = "public." + name
		}
	}
	return got
}

func TestInitRemoteRefusesAHardLinkedCredential(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := seedCredential(t, noDB(t), cfg, "bot", supabaseDSN(t))
	require.NoError(t, os.Link(first.credFile, filepath.Join(t.TempDir(), "copy")))
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "hard link")
}

func TestInitRemoteRunsOneAtATime(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := seedCredential(t, noDB(t), cfg, "bot", supabaseDSN(t))
	unlock, err := PathCredFiles{}.Lock(first.credFile + setup.LockSuffix)
	require.NoError(t, err)
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "another basalt init --remote is running")
	unlock()
	require.Equal(t, cli.ExitOK, cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot").code)
}

// A rootless bot's engine must be able to bind its sockets: with --config
// and no root, init keeps them in a run directory next to the config.
func TestInitRemoteKeepsARootlessSocketDirNextToTheConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "bot", "engine.json")
	r := remoteWith(t, remoteEnv{host: h, login: refusedLogin, probe: noNetworkProbe, noNetwork: true}, cfg, "--agent", "bot")
	require.Equal(t, filepath.Join(filepath.Dir(cfg), "run"), r.cfg.SocketDir)
}

// systemSocketHost is a host that keeps the sockets in the system directory
// the way root's init does, so tests with long temp directories keep short
// socket paths. The test for the rootless path builds its own host.
func systemSocketHost(t *testing.T) *fakeHost {
	t.Helper()
	h := newFakeHost(t)
	h.euid = 0
	return h
}

// sudo is noDB run with sudo by uid (no SUDO_UID when uid is "").
func sudo(t *testing.T, uid string) remoteEnv {
	t.Helper()
	e := noDB(t)
	if uid != "" {
		e.env = map[string]string{setup.EnvSudoUID: uid}
	}
	return e
}

// As root (sudo), init --remote records the user who ran sudo as a person
// the engine's person socket admits, so basalt status --agent works there
// against a service engine; without SUDO_UID, or SUDO_UID 0, it records
// none.
func TestInitRemoteAsRootRecordsTheSudoUser(t *testing.T) {
	t.Parallel()
	cfg := withState(t, tempConfig(t))
	r := remoteWith(t, sudo(t, "1234"), cfg, "--agent", "bot")
	require.Equal(t, []uint32{1234}, r.cfg.PersonUIDs)
	require.True(t, r.cfg.Service(), "a config directory another user owns (the engine's) is a service config")
	require.Contains(t, r.stderr, "not root or you (uid 1234): this config is a service one (mode SERVICE)", "said, not silent")
	r = remoteWith(t, sudo(t, "1235"), cfg, "--agent", "bot")
	require.Equal(t, []uint32{1234, 1235}, r.cfg.PersonUIDs, "a rerun keeps the recorded ones")

	other := withState(t, tempConfig(t))
	r = remoteWith(t, sudo(t, "0"), other, "--agent", "bot")
	require.Empty(t, r.cfg.PersonUIDs, "never root")
	r = remoteWith(t, sudo(t, ""), other, "--agent", "bot")
	require.Empty(t, r.cfg.PersonUIDs)
	require.False(t, r.cfg.Service(), "no person to admit: not a service config")
}

// As root, the service-mode note comes only once engine.json is written:
// never on a run refused before, whether at agents/ (a symlink) or after
// both directories opened (a symlinked lock file).
func TestInitRemoteAsRootNotesServiceModeOnlyAfterWriting(t *testing.T) {
	t.Parallel()
	e := sudo(t, "1234")
	cfg := withState(t, tempConfig(t))
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(filepath.Dir(cfg), "agents")))
	r := e.cli(t, "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code, r.stdout)
	require.Contains(t, r.stderr, "a symlink is refused")
	require.NotContains(t, r.stderr, "service one", "refused at agents/: nothing written")

	cfg = withState(t, tempConfig(t))
	agents := filepath.Join(filepath.Dir(cfg), "agents")
	require.NoError(t, os.MkdirAll(agents, 0o700))
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "lock"), filepath.Join(agents, "bot.url"+setup.LockSuffix)))
	r = e.cli(t, "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code, r.stderr)
	require.NotContains(t, r.stderr, "service one", "refused at the lock, after opening the directories: nothing written")
	_, err := os.Stat(cfg)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, os.Remove(filepath.Join(agents, "bot.url"+setup.LockSuffix)))
	r = e.cli(t, "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Equal(t, 1, strings.Count(r.stderr, "this config is a service one (mode SERVICE)"), "said once, after writing: %s", r.stderr)
}

// As root, a config directory the user who ran sudo owns is that user's own
// engine (same-user mode), not a service one.
func TestInitRemoteAsRootInTheSudoUsersDirectoryIsNoService(t *testing.T) {
	t.Parallel()
	me := strconv.Itoa(os.Geteuid())
	r := remoteWith(t, sudo(t, me), withState(t, tempConfig(t)), "--agent", "bot")
	require.False(t, r.cfg.Service())
	require.NotContains(t, r.stderr, "service one")
}

// A person-operated engine is refused with what to run instead, and the
// help names only --agent.
func TestInitRemoteRefusesAPersonOperatedEngine(t *testing.T) {
	t.Parallel()
	cfg := withState(t, tempConfig(t))
	remote(t, cfg, "--agent", "bot")
	editConfig(t, cfg, func(c *config.Config) { c.OperatedBy = "PERSON"; c.Vault = "" })
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot")
	require.Equal(t, cli.ExitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "this engine is person-operated")

	help := cliNoDB(t, "init", "--remote", "-h")
	require.True(t, slices.Contains([]int{cli.ExitOK, cli.ExitUsage}, help.code), help.stderr)
	require.Contains(t, help.stderr, "-agent")
	for _, gone := range []string{"-write", "-database-url", "-new-code", "-forget", "-json"} {
		require.NotContains(t, help.stderr, gone)
	}
}
