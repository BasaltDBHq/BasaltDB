package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

const (
	supabaseURL = "postgresql://postgres.abcdefghijklmnopqrst@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
	supabaseRef = "abcdefghijklmnopqrst"
)

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{4}( [0-9a-f]{4}){4}$`)

// remoteRun is one basalt init --remote with its files.
type remoteRun struct {
	result
	res      RemoteInitResult
	payload  setupcode.Payload
	cfg      config.Config
	credFile string
}

// refusedLogin stands in for a database that refuses the agent's login
// (its role does not exist yet), so tests without Postgres reach no network.
func refusedLogin(context.Context, string) (agentConn, error) { return nil, errLoginRefused }

// noNetworkProbe stands in for the TLS probe of a new credential
// (hardenedCredential): a database that cannot be reached, so tests without
// Postgres never dial the example hosts (Supabase's pooler among them).
func noNetworkProbe(context.Context, string) error { return context.DeadlineExceeded }

// cliNoDB runs basalt init with every agent login refused.
func cliNoDB(t *testing.T, args ...string) result {
	t.Helper()
	return cliNoDBProbe(t, noNetworkProbe, args...)
}

// cliNoDBProbe is cliNoDB with probe answering the TLS probes.
func cliNoDBProbe(t *testing.T, probe func(context.Context, string) error, args ...string) result {
	t.Helper()
	return cliNoDBEnv(t, probe, nil, args...)
}

// cliNoDBEnv is cliNoDBProbe with env added to the environment.
func cliNoDBEnv(t *testing.T, probe func(context.Context, string) error, env map[string]string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return "postgres://admin:adminsecret@db.example.com/postgres"
			}
			return env[k]
		})
	c.agentLogin = refusedLogin
	c.probe = probe
	c.host = systemSocketHost(t)
	code := runInit(c, args[1:])
	return result{code, stdout.String(), stderr.String()}
}

// remote runs basalt init --remote --json with the engine config at cfg,
// with every agent login refused.
func remote(t *testing.T, cfg string, args ...string) remoteRun {
	t.Helper()
	return remoteWith(t, cliNoDB, cfg, args...)
}

// remoteDBRun is remote against a real database.
func remoteDBRun(t *testing.T, cfg string, args ...string) remoteRun {
	t.Helper()
	run := func(t *testing.T, args ...string) result {
		t.Helper()
		return cli(t, map[string]string{envAdminURL: "postgres://admin:adminsecret@db.example.com/postgres"}, "", args...)
	}
	return remoteWith(t, run, cfg, args...)
}

func remoteWith(t *testing.T, run func(*testing.T, ...string) result, cfg string, args ...string) remoteRun {
	t.Helper()
	all := append([]string{"init", "--remote", "--config", cfg, "--json"}, args...)
	r := remoteRun{result: run(t, all...)}
	require.Equal(t, exitOK, r.code, r.stderr)
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&r.res))
	p, err := setupcode.Decode(r.res.Code)
	require.NoError(t, err)
	r.payload = p
	r.cfg, err = config.Load(cfg)
	require.NoError(t, err)
	r.credFile = r.cfg.Agents[0].CredentialFile
	return r
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
	require.NotContains(t, string(raw), "adminsecret")
	require.NotContains(t, r.stdout+r.stderr, "adminsecret", "BASALT_ADMIN_DATABASE_URL is ignored")
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

func TestInitRemoteRefusesAPasswordBeforeAnythingElse(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--agent", "bot", "--write", "public.leads", "--database-url", "postgres://postgres:hunter2pw@db.example.com:5432/postgres"},
		{"--database-url=postgres://postgres@db.example.com/postgres?sslmode=require&password=hunter2pw", "--agent", "bot"},
		{"--database-url", "host=db.example.com user=postgres password=hunter2pw dbname=postgres"},
		{"--database-url", "host=db.example.com user=postgres PASSWORD = 'hunter2pw' dbname=postgres"},
		{"--database-url", "postgres://postgres:hunter2pw[@db.example.com/postgres", "--nope"},
		{"--agent", "Bad-Name", "--database-url", "postgresql://postgres.ref:hunter2pw@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"},
	} {
		cfg := tempConfig(t)
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, args...)...)
		require.Equal(t, exitError, r.code, "%v: %s", args, r.stderr)
		require.Equal(t, "basalt: "+setupcode.ErrHasPassword.Error()+"\n", r.stderr)
		require.Empty(t, r.stdout)
		require.NotContains(t, r.stderr, "hunter2pw")
		require.NoDirExists(t, filepath.Dir(cfg), "nothing is written")
	}
}

func TestInitRemoteUsage(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	for _, args := range [][]string{
		{"--write", "public.leads", "--database-url", supabaseURL}, // no --agent
		{"--agent", "bot", "--write", "public.leads"},              // first run without --database-url
		{"--agent", "bot", "--database-url", supabaseURL, "--yes"}, // admin init's flags are not --remote's
		{"--agent", "bot", "--database-url", supabaseURL, "--operated-by", "bot"},
		{"--agent", "bot", "--write", "public.Leads", "--database-url", supabaseURL}, // not a plain lowercase table
		{"--agent", "bot", "--write", "public.leads", "--database-url", "postgres://postgres@db.example.com"},
	} {
		r := cliNoDB(t, append([]string{"init", "--remote", "--config", cfg}, args...)...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, r.stdout)
	}
	require.NoFileExists(t, cfg)
	// Admin init does not take --remote's flags.
	require.Equal(t, exitUsage, cli(t, nil, "", "init", "--agent", "bot", "--new-code").code)
}

func TestInitRemoteFirstRunMakesAnInstallCode(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	r := remote(t, cfg, "--agent", "lead_bot", "--write", "public.leads", "--read", "public.companies",
		"--operated-by", "agent", "--database-url", strings.Replace(supabaseURL, "@", ":[YOUR-PASSWORD]@", 1))

	// The credential holds the agent's own connection string, 0600; only
	// its verifier is in the code.
	pw := credentialPassword(t, r.credFile)
	require.Len(t, pw, 64, "256 bits, hex")
	requireNoSecret(t, r, cfg, pw)
	raw, err := os.ReadFile(r.credFile)
	require.NoError(t, err)
	require.Contains(t, string(raw), "postgresql://"+guard.DefaultPrefix+"_agent_lead_bot."+supabaseRef+":")

	p := r.payload
	require.Equal(t, setupcode.KindInstall, p.Kind)
	require.Equal(t, setupcode.Target{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: supabaseRef}, p.Target)
	require.Equal(t, setupcode.Guard{From: 0, To: guard.LatestVersion()}, p.Guard)
	require.Equal(t, []string{"public.leads"}, p.Agent.Write)
	require.Equal(t, []string{"public.companies"}, p.Agent.Read)
	require.Equal(t, guard.DefaultStatementTimeout.Milliseconds(), p.Agent.StatementTimeoutMs)
	requireVerifierOf(t, p.Agent.Verifier, pw)
	created, err := p.CreatedAt()
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), created, time.Minute)
	require.Equal(t, created.Add(24*time.Hour).Truncate(time.Second).Format(time.RFC3339), p.ExpiresAt)

	// The result.
	require.Equal(t, "lead_bot", r.res.Agent)
	require.Equal(t, p.SetupID, r.res.SetupID)
	require.Equal(t, "INSTALL", r.res.Kind)
	require.False(t, r.res.Reused)
	require.Equal(t, p.ExpiresAt, r.res.ExpiresAt)
	require.Equal(t, p.Fingerprint(), r.res.Fingerprint)
	require.Regexp(t, fingerprintPattern, r.res.Fingerprint)
	requireSetupGuidance(t, r.res)

	// engine.json: operatedBy, the portal and the pending setup, no secret.
	require.Equal(t, "AGENT", r.cfg.OperatedBy)
	require.Equal(t, links.Portal, r.cfg.PagesURL)
	a := r.cfg.Agents[0]
	require.Equal(t, filepath.Join(filepath.Dir(cfg), "agents", "lead_bot.url"), a.CredentialFile)
	require.Equal(t, &config.Setup{
		SetupID: p.SetupID, Kind: "INSTALL", GuardVersion: guard.LatestVersion(),
		ExpiresAt: p.ExpiresAt, Code: r.res.Code, Fingerprint: r.res.Fingerprint,
	}, a.Setup)
	require.Contains(t, a.InitArgs, "--operated-by=agent")
	_, err = agent.NewCommands(a.Name, cfg, "linux", a.InitArgs)
	require.NoError(t, err, "the saved flags are ones the engine accepts")
	pages, err := r.cfg.Pages()
	require.NoError(t, err)
	require.Empty(t, pages.Addr, "the engine serves no local pages for the portal")

	// Text output: the code on a line of its own and the fingerprint.
	txt := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "lead_bot", "--write", "public.leads",
		"--read", "public.companies", "--operated-by", "agent")
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "\n\n"+r.res.Code+"\n\n")
	require.Contains(t, txt.stdout, "Setup fingerprint: "+r.res.Fingerprint+"\n")
	require.NotContains(t, txt.stdout+txt.stderr, pw)
}

// requireSetupGuidance checks the person message and the steps against the
// contract and the catalog.
func requireSetupGuidance(t *testing.T, res RemoteInitResult) {
	t.Helper()
	pm := res.PersonMessage
	require.Contains(t, pm, res.Fingerprint)
	require.Contains(t, pm, "Never paste your database password")
	require.Contains(t, pm, "\n"+releasePage+"\n", "the URL stands on a line of its own")
	require.LessOrEqual(t, utf8.RuneCountInString(strings.Replace(pm, releasePage, "", 1)), agent.MaxPersonMessageLength)

	catalog, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	var want []mcpcontract.StepKind
	for _, p := range catalog.Problems {
		if p.Code == "SETUP_NOT_RUN" {
			want = p.Steps
		}
	}
	got := make([]mcpcontract.StepKind, 0, len(res.NextSteps))
	for _, s := range res.NextSteps {
		got = append(got, mcpcontract.StepKind{Actor: s.Actor, Action: s.Action})
	}
	require.Equal(t, want, got, "P RUN_COMMAND, P TELL_AGENT, A END_TURN, A CALL_TOOL status")
	require.Equal(t, "basalt init --setup-code "+res.Code, res.NextSteps[0].Command)
	require.Equal(t, "status", res.NextSteps[3].Tool)
}

// A new credential keeps the strongest TLS protection the probe confirms,
// and init says which in one line: through Supabase's pooler, which
// answers before any SASL message, a verified certificate without channel
// binding.
func TestInitRemoteHardensTheCredentialThroughThePooler(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	var probed []string
	probe := func(_ context.Context, dsn string) error {
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		probed = append(probed, u.Query().Get(paramSSLMode)+"/"+u.Query().Get(paramChannelBinding))
		return &pgconn.PgError{Code: sqlstateInternal, Message: supavisorNoTenant}
	}
	run := func(t *testing.T, args ...string) result { t.Helper(); return cliNoDBProbe(t, probe, args...) }
	r := remoteWith(t, run, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	require.Equal(t, []string{"verify-full/require", "verify-full/"}, probed)
	raw, err := os.ReadFile(r.credFile)
	require.NoError(t, err)
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	require.Equal(t, sslVerifyFull, u.Query().Get(paramSSLMode))
	require.Empty(t, u.Query().Get(paramChannelBinding))
	const line = "basalt: connection protected: database identity verified (channel binding not available through the Supabase pooler)\n"
	require.Equal(t, 1, strings.Count(r.stderr, line), r.stderr)
	requireNoSecret(t, r, cfg, credentialPassword(t, r.credFile))
}

func TestInitRemoteCredentialDropsTheURLsLoginParams(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	const canary = "zzcanary"
	r := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url",
		"postgres://app@db.example.com:5432/crm?sslmode=require&user="+canary+"user&passfile=/"+canary+"/passfile&sslkey=/"+canary+"/key.pem")

	raw, err := os.ReadFile(r.credFile)
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary)
	pc, err := pgx.ParseConfig(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	require.Equal(t, guard.DefaultPrefix+"_agent_bot", pc.User)
	require.Equal(t, credentialPassword(t, r.credFile), pc.Password)
	require.Equal(t, "db.example.com", pc.Host)
	require.Equal(t, "crm", pc.Database)
	require.NotNil(t, pc.TLSConfig, "sslmode is kept")
	require.Empty(t, pc.TLSConfig.Certificates, "the admin's sslkey is not the agent's")
}

func TestInitRemoteRefusesTargetParams(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	for _, param := range []string{"host=other.example.com", "port=6000", "dbname=other"} {
		r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads",
			"--database-url", "postgres://app@db.example.com:5432/crm?"+param)
		require.Equal(t, exitUsage, r.code, "%s: %s", param, r.stderr)
		require.Contains(t, r.stderr, "put the host, port and database in the URL itself", param)
		require.Empty(t, r.stdout)
	}
	require.NoFileExists(t, cfg)
}

// basalt init keeps host, port and dbname parameters in the credential it
// writes; --remote can't target such a URL. It says so and leaves the file,
// the running engine's credential, as it is.
func TestInitRemoteExplainsACredentialWithTargetParams(t *testing.T) {
	t.Parallel()
	const stored = "postgres://basalt_agent_bot:enginepw@db.example.com:5432/crm?sslmode=require&host=10.0.0.9\n"
	for _, suffix := range []string{"", pendingSuffix} {
		for _, extra := range [][]string{nil, {"--database-url", "postgres://app@db.example.com:5432/crm"}} {
			cfg := tempConfig(t)
			path := filepath.Join(filepath.Dir(cfg), "agents", "bot.url"+suffix)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(stored), config.FileMode))

			args := append([]string{"init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads"}, extra...)
			r := cliNoDB(t, args...)

			require.Equal(t, exitError, r.code, "%q %v: %s", suffix, extra, r.stderr)
			require.Contains(t, r.stderr, "was written by basalt init for a connection string with a host= parameter")
			require.Contains(t, r.stderr, "Use another --agent name, or another --config")
			require.NotContains(t, r.stderr, "enginepw")
			require.Empty(t, r.stdout)
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, stored, string(raw), "the credential is not overwritten")
			require.NoFileExists(t, cfg)
		}
	}
}

func TestInitRemoteRerunPrintsThePendingCode(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	args := []string{"--agent", "bot", "--write", "public.leads"}
	first := remote(t, cfg, append(args, "--database-url", supabaseURL)...)
	pw := credentialPassword(t, first.credFile)

	again := remote(t, cfg, args...)
	require.True(t, again.res.Reused)
	require.Contains(t, again.stderr, "--new-code makes a new one")
	require.Equal(t, first.res.SetupID, again.res.SetupID)
	require.Equal(t, first.res.ExpiresAt, again.res.ExpiresAt)
	require.Equal(t, first.res.Code, again.res.Code)
	require.Equal(t, pw, credentialPassword(t, first.credFile))

	// --new-code: a new setupId and expiry; still an INSTALL while the role
	// does not log in, with the password this machine holds.
	fresh := remote(t, cfg, append(args, "--new-code")...)
	require.False(t, fresh.res.Reused)
	require.NotEqual(t, first.res.SetupID, fresh.res.SetupID)
	require.Equal(t, "INSTALL", fresh.res.Kind)
	require.Equal(t, pw, credentialPassword(t, first.credFile))
	requireVerifierOf(t, fresh.payload.Agent.Verifier, pw)
	require.NotEqual(t, first.res.Fingerprint, fresh.res.Fingerprint)

	// A change of tables makes a new code too.
	changed := remote(t, cfg, "--agent", "bot", "--write", "public.leads,public.notes")
	require.NotEqual(t, fresh.res.SetupID, changed.res.SetupID)
	require.Equal(t, []string{"public.leads", "public.notes"}, changed.payload.Agent.Write)
	requireNoSecret(t, changed, cfg, pw)
}

func TestInitRemoteReplacesAnExpiredCode(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	c, err := config.Load(cfg)
	require.NoError(t, err)
	c.Agents[0].Setup.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))

	again := remote(t, cfg, "--agent", "bot", "--write", "public.leads")
	require.False(t, again.res.Reused)
	require.NotEqual(t, first.res.SetupID, again.res.SetupID)
}

func TestInitRemoteRefusesASymlinkedCredential(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	target := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte("postgres://x@h/db\n"), 0o600))
	require.NoError(t, os.Remove(first.credFile))
	require.NoError(t, os.Symlink(target, first.credFile))

	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "is not usable")
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "postgres://x@h/db\n", string(raw), "the link's target is untouched")

	// A .pending planted as a link is refused the same way.
	require.NoError(t, os.Remove(first.credFile))
	u, err := url.Parse(supabaseURL)
	require.NoError(t, err)
	u.User = url.UserPassword(u.User.Username(), "0123abcd")
	require.NoError(t, config.WriteFile(first.credFile, []byte(u.String()+"\n")))
	require.NoError(t, os.Symlink(target, first.credFile+pendingSuffix))
	r = cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, pendingSuffix+" is not usable")

	// config.WriteFile, which writes every file init writes, refuses a link.
	require.Error(t, config.WriteFile(first.credFile+pendingSuffix, []byte("x")))
	raw, err = os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "postgres://x@h/db\n", string(raw))
}

func TestInitRemoteRefusesALongCode(t *testing.T) {
	t.Parallel()
	tables := make([]string, 0, 60)
	for i := range 60 {
		sum := sha256.Sum256([]byte{byte(i)})
		tables = append(tables, "public.t"+hex.EncodeToString(sum[:20]))
	}
	cfg := tempConfig(t)
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", strings.Join(tables, ","),
		"--database-url", supabaseURL)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "name fewer tables")
	require.NoFileExists(t, cfg)
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

// runCode does what the person's computer does with an INSTALL or AGENT
// code: the role from the verifier, the grants and record_setup, in one
// transaction as the admin.
func runCode(t *testing.T, d *guardtest.DB, p setupcode.Payload) {
	t.Helper()
	ctx := context.Background()
	spec := guard.AgentSpec{}
	agentName := ""
	if p.Agent != nil {
		agentName = p.Agent.Name
		spec = guard.AgentSpec{
			Name: p.Agent.Name, Write: p.Agent.Write, Read: p.Agent.Read,
			Verifier: p.Agent.Verifier, CreateOnly: p.Kind == setupcode.KindInstall,
			StatementTimeout: time.Duration(p.Agent.StatementTimeoutMs) * time.Millisecond,
		}
	}
	expires, err := p.ExpiresTime()
	require.NoError(t, err)
	id, err := uuid.Parse(p.SetupID)
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error {
		if p.Agent != nil {
			s, err := guard.PlanInit(ctx, tx, guard.InitOptions{Names: d.Names, Agent: spec})
			if err != nil {
				return err
			}
			if err := s.Apply(ctx, tx); err != nil {
				return err
			}
		}
		_, err := guard.RecordSetup(ctx, tx, d.Names, guard.Setup{
			ID: id, Kind: string(p.Kind), Agent: agentName,
			GuardVersion: p.Guard.To, ExpiresAt: expires,
		})
		return err
	}))
}

func TestInitRemoteAgainstTheDatabase(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	base := []string{"--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix}

	// INSTALL, run by the person: the bot's password now logs in.
	install := remoteDBRun(t, cfg, append(base, "--database-url", dbURL)...)
	require.Equal(t, "INSTALL", install.res.Kind)
	pw := credentialPassword(t, install.credFile)
	runCode(t, d, install.payload)

	// The setup is recorded: a re-run makes a new code, an AGENT code with
	// no change and no verifier, since the guard is this build's.
	noChange := remoteDBRun(t, cfg, base...)
	require.Equal(t, "AGENT", noChange.res.Kind)
	require.NotEqual(t, install.res.SetupID, noChange.res.SetupID)
	require.Empty(t, noChange.payload.Agent.Verifier)
	require.Equal(t, setupcode.Guard{From: guard.LatestVersion(), To: guard.LatestVersion()}, noChange.payload.Guard)
	require.Equal(t, pw, credentialPassword(t, install.credFile))

	// Pending and unchanged: the same code again.
	again := remoteDBRun(t, cfg, base...)
	require.True(t, again.res.Reused)
	require.Equal(t, noChange.res.SetupID, again.res.SetupID)

	// A change of tables: AGENT, password kept.
	changed := remoteDBRun(t, cfg, "--agent", "bot", "--write", "public.leads", "--read", "public.lead_notes", "--prefix", d.Names.Prefix)
	require.Equal(t, "AGENT", changed.res.Kind)
	require.Empty(t, changed.payload.Agent.Verifier)
	require.Equal(t, []string{"public.lead_notes"}, changed.payload.Agent.Read)

	// --new-code: a new password, in .pending until the person runs it; the
	// old one keeps working.
	rotate := remoteDBRun(t, cfg, append(base, "--new-code")...)
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.Equal(t, pw, credentialPassword(t, install.credFile))
	pw2 := credentialPassword(t, install.credFile+pendingSuffix)
	require.NotEqual(t, pw, pw2)
	requireVerifierOf(t, rotate.payload.Agent.Verifier, pw2)
	requireNoSecret(t, rotate, cfg, pw2)
	requireNoSecret(t, rotate, cfg, pw)

	// The person runs it: the next run logs in with .pending and moves it
	// over the credential file.
	runCode(t, d, rotate.payload)
	after := remoteDBRun(t, cfg, base...)
	require.False(t, after.res.Reused)
	require.Equal(t, pw2, credentialPassword(t, install.credFile))
	require.NoFileExists(t, install.credFile+pendingSuffix)

	// UPGRADE when the guard is older than the build: no agent part.
	runCode(t, d, after.payload)
	d.Exec(t, fmt.Sprintf(`DELETE FROM basalt_meta.schema_version WHERE version = %d`, guard.LatestVersion()))
	upgrade := remoteDBRun(t, cfg, base...)
	require.Equal(t, "UPGRADE", upgrade.res.Kind)
	require.Nil(t, upgrade.payload.Agent)
	require.Equal(t, setupcode.Guard{From: guard.LatestVersion() - 1, To: guard.LatestVersion()}, upgrade.payload.Guard)
	require.Equal(t, pw2, credentialPassword(t, install.credFile))
}

func TestInitRemoteRefusedLoginMakesAnInstallCode(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	base := []string{"--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix}
	install := remoteDBRun(t, cfg, append(base, "--database-url", dbURL)...)
	runCode(t, d, install.payload)
	// Someone else's password for the role: the bot cannot log in.
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	d.Exec(t, `ALTER ROLE `+pgx.Identifier{role}.Sanitize()+` PASSWORD 'not-the-bots'`)

	clearSetup(t, cfg) // the engine saw the setup recorded
	r := remoteDBRun(t, cfg, base...)
	require.Equal(t, "INSTALL", r.res.Kind, "the role cannot log in")

	// --new-code once the install had run: an AGENT code with a new
	// password (RI-17), kept in .pending: the refusal could have been
	// transient, so the credential file stays as it is.
	clearSetup(t, cfg)
	pw := credentialPassword(t, install.credFile)
	rotate := remoteDBRun(t, cfg, append(base, "--new-code")...)
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.Equal(t, pw, credentialPassword(t, install.credFile))
	pw2 := credentialPassword(t, install.credFile+pendingSuffix)
	require.NotEqual(t, pw, pw2)
	requireVerifierOf(t, rotate.payload.Agent.Verifier, pw2)

	// The person runs it: .pending logs in and replaces the credential.
	runCode(t, d, rotate.payload)
	after := remoteDBRun(t, cfg, base...)
	require.Equal(t, "AGENT", after.res.Kind, "the bot logs in again")
	require.Equal(t, pw2, credentialPassword(t, install.credFile))
	require.NoFileExists(t, install.credFile+pendingSuffix)
}

func TestInitRemoteNeverOverwritesTheCredential(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	args := []string{"--agent", "bot", "--write", "public.leads"}
	first := remote(t, cfg, append(args, "--database-url", supabaseURL)...)
	pw := credentialPassword(t, first.credFile)
	runAsFinished(t, cfg)

	// A refused login (perhaps a pooler hiccup) then --new-code: the new
	// password waits in .pending; the credential that may still work stays.
	rotate := remote(t, cfg, append(args, "--new-code")...)
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.Equal(t, pw, credentialPassword(t, first.credFile))
	pw2 := credentialPassword(t, first.credFile+pendingSuffix)
	require.NotEqual(t, pw, pw2)
	requireVerifierOf(t, rotate.payload.Agent.Verifier, pw2)

	// Another database: an INSTALL code whose password waits in .pending.
	other := remote(t, cfg, append(args, "--database-url", "postgres://app@db.example.com:5432/crm")...)
	require.Equal(t, "INSTALL", other.res.Kind)
	require.Equal(t, setupcode.Target{Host: "db.example.com", Port: 5432, Database: "crm"}, other.payload.Target)
	require.Equal(t, pw, credentialPassword(t, first.credFile))
	pw3 := credentialPassword(t, first.credFile+pendingSuffix)
	requireVerifierOf(t, other.payload.Agent.Verifier, pw3)
	// A re-run without --database-url follows the pending setup's database.
	again := remote(t, cfg, args...)
	require.True(t, again.res.Reused)
	require.Equal(t, other.res.SetupID, again.res.SetupID)
}

// runAsFinished drops the pending setup, as the engine does once it sees
// the setup recorded.
func runAsFinished(t *testing.T, cfg string) {
	t.Helper()
	clearSetup(t, cfg)
}

func TestInitRemoteRefusesAHardLinkedCredential(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	require.NoError(t, os.Link(first.credFile, filepath.Join(t.TempDir(), "copy")))
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "hard link")
}

func TestInitRemoteRunsOneAtATime(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", supabaseURL)
	unlock, err := lockFile(first.credFile + lockSuffix)
	require.NoError(t, err)
	r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "another basalt init --remote is running")
	unlock()
	require.Equal(t, exitOK, cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", "bot", "--write", "public.leads").code)
}

func TestSetupPersonMessageFitsForTheLongestName(t *testing.T) {
	t.Parallel()
	name := ""
	for n := 1; n < 100; n++ {
		if candidate := strings.Repeat("a", n); config.ValidAgentName(candidate) {
			name = candidate
		}
	}
	require.GreaterOrEqual(t, len(name), 50)
	pm := setupPersonMessage(name, "3f9a 21c0 7d44 e1b2 90ac")
	withoutURL := strings.Replace(pm, releasePage+"\n", "", 1)
	require.LessOrEqual(t, utf8.RuneCountInString(withoutURL), agent.MaxPersonMessageLength, pm)
	require.Equal(t, 1, strings.Count(pm, name), "the agent is named once")
}

// clearSetup drops the pending setup from engine.json, as the engine does
// when it finds the setup recorded.
func clearSetup(t *testing.T, cfg string) {
	t.Helper()
	c, err := config.Load(cfg)
	require.NoError(t, err)
	c.Agents[0].Setup = nil
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
}

func TestCheckBuildVersion(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"0.0.1", "0.0.1-alpha.2", "0.0.1-alpha.1-295-gced6c31", "1.2.3"} {
		require.NoError(t, checkBuildVersion(ok), ok)
	}
	for _, bad := range []string{"dev", "master-ced6c31", "", "0.0"} {
		err := checkBuildVersion(bad)
		require.Error(t, err, bad)
		require.NotErrorIs(t, err, errUsage)
		require.Contains(t, err.Error(), "install a release build")
	}
}

// A rootless bot's engine must be able to bind its sockets: with --config
// and no root, init keeps them in a run directory next to the config.
func TestInitRemoteKeepsARootlessSocketDirNextToTheConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "bot", "engine.json")
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return "postgres://admin:adminsecret@db.example.com/postgres"
			}
			return ""
		})
	c.host = h
	c.agentLogin = refusedLogin
	code := runInit(c, []string{
		"--remote", "--config", cfg, "--json", "--agent", "bot", "--write", "public.leads",
		"--database-url", "postgres://postgres@db.example.com:5432/postgres",
	})
	require.Equal(t, exitOK, code, stderr.String())
	loaded, err := config.Load(cfg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(filepath.Dir(cfg), "run"), loaded.SocketDir)
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

// As root (sudo), init --remote records the user who ran sudo as a person
// the engine's person socket admits, so basalt status --agent works there
// against a service engine; without SUDO_UID, or SUDO_UID 0, it records
// none.
func TestInitRemoteAsRootRecordsTheSudoUser(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	args := []string{"--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app"}
	run := func(env map[string]string) func(*testing.T, ...string) result {
		return func(t *testing.T, a ...string) result { t.Helper(); return cliNoDBEnv(t, noNetworkProbe, env, a...) }
	}
	r := remoteWith(t, run(map[string]string{envSudoUID: "1234"}), cfg, args...)
	require.Equal(t, []uint32{1234}, r.cfg.PersonUIDs)
	require.True(t, r.cfg.Service(), "a config directory another user owns (the engine's) is a service config")
	require.Contains(t, r.stderr, "not root or you (uid 1234): this config is a service one (mode SERVICE)", "said, not silent")
	r = remoteWith(t, run(map[string]string{envSudoUID: "1235"}), cfg, append(args, "--new-code")...)
	require.Equal(t, []uint32{1234, 1235}, r.cfg.PersonUIDs, "a rerun keeps the recorded ones")

	other := tempConfig(t)
	r = remoteWith(t, run(map[string]string{envSudoUID: "0"}), other, args...)
	require.Empty(t, r.cfg.PersonUIDs, "never root")
	r = remoteWith(t, run(nil), other, append(args, "--new-code")...)
	require.Empty(t, r.cfg.PersonUIDs)
	require.False(t, r.cfg.Service(), "no person to admit: not a service config")
}

// As root, a config directory the user who ran sudo owns is that user's own
// engine (same-user mode), not a service one.
func TestInitRemoteAsRootInTheSudoUsersDirectoryIsNoService(t *testing.T) {
	t.Parallel()
	me := strconv.Itoa(os.Geteuid())
	r := remoteWith(t, func(t *testing.T, a ...string) result {
		t.Helper()
		return cliNoDBEnv(t, noNetworkProbe, map[string]string{envSudoUID: me}, a...)
	}, tempConfig(t), "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	require.False(t, r.cfg.Service())
	require.NotContains(t, r.stderr, "service one")
}
