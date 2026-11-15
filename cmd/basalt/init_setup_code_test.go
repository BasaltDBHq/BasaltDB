package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// laptopRun is basalt init --setup-code on the person's computer: the admin
// connection string in the environment, stdin, a fixed randomness source
// (so the passkey request is known) and the clock at now (zero: the real
// clock).
func laptopRun(t *testing.T, admin, stdin string, now time.Time, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return admin
			}
			return ""
		})
	c.rand = fixedRand()
	if !now.IsZero() {
		c.now = func() time.Time { return now }
	}
	code := runInit(c, args)
	return result{code, stdout.String(), stderr.String()}
}

// portalPasskey is the person's software passkey for the portal and the
// code its registration page shows for database db.
func portalPasskey(t *testing.T, db string) (*passkeytest.Authenticator, string) {
	t.Helper()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	return person, registrationCode(t, person, db)
}

// installed runs an INSTALL code made by basalt init --remote through
// basalt init --setup-code, registering a portal passkey, and returns the
// bot's run.
func installed(t *testing.T, d *guardtest.DB, dbURL, cfg string, tables ...string) remoteRun {
	t.Helper()
	args := append([]string{"--agent", "bot", "--prefix", d.Names.Prefix, "--database-url", dbURL}, tables...)
	install := remoteDBRun(t, cfg, args...)
	require.Equal(t, "INSTALL", install.res.Kind)
	_, reg := portalPasskey(t, dbName(t, d))
	r := laptopRun(t, d.URL, reg+"\n", time.Time{}, "--setup-code", install.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	return install
}

// agentLogsIn reports whether the agent's credential file logs in and its
// setup is recorded, as the engine checks when it finishes a setup.
func agentLogsIn(t *testing.T, credFile, setupID string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, credentialDSN(t, credFile))
	if err != nil {
		return false
	}
	defer conn.Close(ctx)
	found, err := guard.SetupRecorded(ctx, conn, uuid.MustParse(setupID))
	require.NoError(t, err)
	return found
}

func credentialDSN(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func installedVersion(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	return v
}

func TestInitSetupCodeInstallsFromTheLaptop(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	install := remoteDBRun(t, cfg, "--agent", "bot", "--write", "public.leads", "--read", "public.payroll",
		"--prefix", d.Names.Prefix, "--database-url", dbURL)
	require.False(t, agentLogsIn(t, install.credFile, install.res.SetupID), "the role does not exist yet")

	person, reg := portalPasskey(t, dbName(t, d))
	r := laptopRun(t, d.URL, reg+"\n", time.Time{}, "--setup-code", install.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)

	// Words first, then the SQL with the verifier and record_setup last.
	role := d.Names.Prefix + "_agent_bot"
	require.Contains(t, r.stdout, "This creates the agent bot (role "+role+").")
	require.Contains(t, r.stdout, "Setup fingerprint: "+install.res.Fingerprint+". Check that bot shows the same fingerprint.")
	require.Contains(t, r.stdout, "bot will be able to read public.payroll and change rows in public.leads, up to 10 rows")
	require.Less(t, strings.Index(r.stdout, "This creates the agent"), strings.Index(r.stdout, "CREATE SCHEMA"))
	require.Contains(t, r.stdout, "PASSWORD '"+install.payload.Agent.Verifier+"'")
	require.Greater(t, strings.Index(r.stdout, "basalt_meta.record_setup("), strings.Index(r.stdout, "attach_all()"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(strings.Split(r.stdout, "Done.")[0]), "::timestamptz);"),
		"record_setup is the last statement")
	require.Contains(t, r.stderr, "https://portal.basaltvault.app/passkeys/register#1.")
	require.Contains(t, r.stderr, "passkey registered for basaltvault.app")
	require.True(t, strings.HasSuffix(r.stdout, "Done. Tell bot to check its status.\n"))

	// The bot's own password now logs in, and it sees its setup recorded.
	require.True(t, agentLogsIn(t, install.credFile, install.res.SetupID))
	keys, err := guard.ActivePasskeys(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, person.ID, keys[0].ID)
	require.Equal(t, "https://portal.basaltvault.app", keys[0].Origin)
	require.NotContains(t, r.stdout+r.stderr, credentialPassword(t, install.credFile), "the agent's password never reaches the laptop")

	// The same code again: refused, nothing asked.
	again := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", install.res.Code, "--yes")
	require.Equal(t, exitError, again.code)
	require.Contains(t, again.stderr, "basalt: This setup code was already used on ")
	require.Contains(t, again.stderr, ". Ask bot for a new one.")
}

func TestInitSetupCodeRefusesBeforeTheDatabase(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	install := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	expires, err := install.payload.ExpiresTime()
	require.NoError(t, err)
	// An admin string that cannot connect: none of these refusals connects.
	const admin = "postgres://admin:adminsecret@127.0.0.1:1/app"

	for name, tc := range map[string]struct {
		now  time.Time
		code string
		want string
	}{
		"expired":         {expires, install.res.Code, "basalt: This setup code expired on " + expires.UTC().Format("2006-01-02 15:04 UTC") + ". Ask bot for a new one.\n"},
		"from the future": {expires.Add(-48 * time.Hour), install.res.Code, "basalt: This setup code claims a time in the future. Check this computer's clock, or ask bot for a new code.\n"},
		"not a code":      {time.Time{}, "hello", "basalt: This is not a Basalt setup code.\n"},
		"damaged":         {time.Time{}, damaged(install.res.Code), "basalt: This setup code is damaged; copy it again.\n"},
		"wrapped and wrong host": {
			time.Time{},
			install.res.Code[:40] + "\n  " + install.res.Code[40:],
			"basalt: This setup code is for database app of db.example.com:5432 (the agent connects there). Your admin connection string points at database app of 127.0.0.1:1. " +
				"Either run this command with the admin connection string of db.example.com:5432, or ask bot for a new code for the database you meant " +
				"(basalt init --remote --new-code --database-url postgres://admin@127.0.0.1:1/app).\n",
		},
	} {
		r := laptopRun(t, admin, "", tc.now, "--setup-code", tc.code, "--yes")
		require.Equal(t, exitError, r.code, name)
		require.Equal(t, tc.want, r.stderr, name)
		require.NotContains(t, r.stderr, "adminsecret", name)
		require.Empty(t, r.stdout, name)
	}
}

// damaged changes the last character of the code's check.
func damaged(code string) string {
	if strings.HasSuffix(code, "A") {
		return code[:len(code)-1] + "B"
	}
	return code[:len(code)-1] + "A"
}

func TestInitSetupCodeUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--setup-code", ""},
		{"--setup-code", "x", "--operated-by", "agent"}, // the agent's machine keeps operatedBy
		{"--setup-code", "x", "--agent", "bot"},
		{"--setup-code", "x", "--remote"},
		{"--setup-code", "x", "--agent-rls", "maybe"},
	} {
		r := laptopRun(t, "", "", time.Time{}, args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
	}

	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
	c.goos = "windows"
	require.Equal(t, exitError, runInit(c, []string{"--setup-code", "x"}))
	require.Contains(t, stderr.String(), "macOS and Linux only")

	require.True(t, isSetupCode([]string{"--setup-code=x"}))
	require.True(t, isSetupCode([]string{"-setup-code", "x"}))
	require.False(t, isSetupCode([]string{"--agent", "bot", "--", "--setup-code"}))
}

func TestSetupTargetMatchesByDatabaseIdentity(t *testing.T) {
	t.Parallel()
	pooler := setupcode.Target{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	plain := setupcode.Target{Host: "db.example.com", Port: 5432, Database: "app"}
	for _, tc := range []struct {
		want  setupcode.Target
		admin string
		same  bool
	}{
		// Supabase: the pooler and the direct host of one project match.
		{pooler, "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres", true},
		{pooler, "postgres://postgres.abcdefghijklmnopqrst:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres", true},
		{pooler, "postgres://postgres:pw@db.zzzzzzzzzzzzzzzzzzzz.supabase.co:5432/postgres", false},
		{pooler, "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/other", false},
		{plain, "postgres://admin:pw@DB.example.com/app", true},
		{plain, "postgres://admin:pw@db.example.com:5433/app", false},
		{plain, "postgres://admin:pw@db.example.com/other", false},
		{plain, "postgres://admin:pw@db2.example.com/app", false},
	} {
		u, err := url.Parse(tc.admin)
		require.NoError(t, err)
		got, err := setupcode.TargetOf(u)
		require.NoError(t, err)
		require.Equal(t, tc.same, sameDatabase(tc.want, got), tc.admin)
	}

	p := setupcode.Payload{Target: pooler, Agent: &setupcode.Agent{Name: "lead_bot"}}
	err := checkSetupTarget(p, "postgres://postgres:secretpw@db.zzzzzzzzzzzzzzzzzzzz.supabase.co:5432/postgres?sslmode=require&password=x")
	require.EqualError(t, err, "This setup code is for database postgres of Supabase project abcdefghijklmnopqrst (the agent connects there). "+
		"Your admin connection string points at database postgres of Supabase project zzzzzzzzzzzzzzzzzzzz. "+
		"Either run this command with the admin connection string of Supabase project abcdefghijklmnopqrst, or ask lead_bot for a new code "+
		"for the database you meant (basalt init --remote --new-code --database-url postgres://postgres@db.zzzzzzzzzzzzzzzzzzzz.supabase.co:5432/postgres).")

	// The URL rules of basalt init, and a host the parameters would change.
	require.ErrorIs(t, checkSetupTarget(p, "host=db user=postgres"), guard.ErrAdminURLForm)
	require.ErrorContains(t, checkSetupTarget(p, "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co/postgres?host=evil.example.com"), "host=")
	require.Error(t, checkSetupTarget(p, "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co/postgres?service=x"))
	require.NoError(t, checkSetupTarget(p, "postgres://postgres:pw@db.abcdefghijklmnopqrst.supabase.co/postgres"))
}

func TestInitSetupCodeWrongDatabaseChangesNothing(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	other := guardtest.New(t).WithDemo(t)
	install := remoteDBRun(t, tempConfig(t), "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--database-url", dbURL)

	r := laptopRun(t, other.URL, "", time.Time{}, "--setup-code", install.res.Code, "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "basalt: This setup code is for database "+dbName(t, d)+" of ")
	require.Contains(t, r.stderr, "Your admin connection string points at database "+dbName(t, other)+" of ")
	require.Zero(t, installedVersion(t, other))
	require.Zero(t, installedVersion(t, d))
}

func TestInitSetupCodeRefusesAnAgentRoleThatIsNotPlain(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	install := installed(t, d, dbURL, cfg, "--write", "public.leads")
	role := d.Names.Prefix + "_agent_bot"

	// Someone gave the agent's role CREATEDB; the bot asks for a new password.
	d.Exec(t, "ALTER ROLE "+role+" CREATEDB")
	rotate := remoteDBRun(t, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	require.Equal(t, "AGENT", rotate.res.Kind)
	require.NotEmpty(t, rotate.payload.Agent.Verifier)

	r := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", rotate.res.Code, "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "This replaces the password of the existing agent bot (role "+role+")")
	require.Contains(t, r.stderr, "LEDGER_INPUT_INVALID")
	require.Contains(t, r.stderr, "is not a plain agent role")
	require.Contains(t, r.stderr, "Nothing changed")

	// The old password still logs in; the new one does not, and the setup
	// is not recorded.
	require.True(t, agentLogsIn(t, install.credFile, install.res.SetupID))
	require.False(t, agentLogsIn(t, install.credFile+pendingSuffix, rotate.res.SetupID))
	setups, err := guard.SetupsFor(context.Background(), d.Admin, uuid.MustParse(rotate.res.SetupID), "")
	require.NoError(t, err)
	require.Empty(t, setups)
}

func TestInitSetupCodeRollsBackEverything(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	install := remoteDBRun(t, tempConfig(t), "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--database-url", dbURL)
	l, err := newLaptopSetup(&cliIO{ctx: context.Background(), now: time.Now}, setupCodeFlags{code: install.res.Code, yes: true, agentRLS: AgentRLSNone})
	require.NoError(t, err)
	l.c = newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	l.conn = d.Admin
	script, err := l.plan()
	require.NoError(t, err)

	// The role appears after the checks: CREATE ROLE fails in Postgres and
	// everything before it (roles, schema, migrations) rolls back.
	role := d.Names.Prefix + "_agent_bot"
	d.Exec(t, "CREATE ROLE "+role+" NOLOGIN")
	err = applySetup(context.Background(), d.Admin, script)
	require.ErrorContains(t, err, "already exists")
	require.Zero(t, installedVersion(t, d))
	var leftovers int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT
		(SELECT count(1) FROM pg_namespace WHERE nspname = 'basalt_meta') +
		(SELECT count(1) FROM pg_roles WHERE rolname IN ($1, $2)) +
		(SELECT count(1) FROM pg_roles WHERE rolname = $3 AND rolcanlogin)`,
		d.Names.Guard(), d.Names.Agents(), role).Scan(&leftovers))
	require.Zero(t, leftovers)

	// A replayed code: record_setup, last in the transaction, refuses it
	// even past the checks, and the role's change rolls back with it.
	d.Exec(t, "DROP ROLE "+role)
	require.NoError(t, applySetup(context.Background(), d.Admin, script))
	require.Equal(t, guard.LatestVersion(), installedVersion(t, d))
	d.Exec(t, "ALTER ROLE "+role+" SET statement_timeout = 5")
	err = applySetup(context.Background(), d.Admin, guard.Script{Statements: append(
		[]guard.Statement{{SQL: "ALTER ROLE " + role + " SET statement_timeout = 99"}}, script.Statements[len(script.Statements)-1])})
	refusal, ok := guard.SetupRefusal(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, guard.SetupUsed, refusal)
	require.ErrorContains(t, l.refused(err), "This setup code was already used on ")
	now, err := guard.RoleStatementTimeout(context.Background(), d.Admin, role)
	require.NoError(t, err)
	require.Equal(t, "5", now.AllDatabases)
}

func TestInitSetupCodeAgentCodeReplacesTheTables(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	install := installed(t, d, dbURL, cfg, "--write", "public.leads", "--read", "public.payroll")
	role := d.Names.Prefix + "_agent_bot"
	d.Exec(t, "ALTER ROLE "+role+" SET statement_timeout = '15s'")

	change := remoteDBRun(t, cfg, "--agent", "bot", "--read", "public.leads", "--prefix", d.Names.Prefix)
	require.Equal(t, "AGENT", change.res.Kind)
	require.Empty(t, change.payload.Agent.Verifier)
	r := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", change.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "This changes the tables of the existing agent bot (role "+role+"); its password stays.")
	require.Contains(t, r.stdout, "statement timeout 30000 ms (now 15000 ms), at most 8 connections.")
	require.NotContains(t, r.stderr, "/passkeys/register", "a portal passkey is registered already")

	// A statement_timeout set for this database only wins over the
	// role's: the summary shows it.
	d.Exec(t, "ALTER ROLE "+role+" IN DATABASE "+pgx.Identifier{dbName(t, d)}.Sanitize()+" SET statement_timeout = '5s'")
	again := remoteDBRun(t, cfg, "--agent", "bot", "--read", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	r = laptopRun(t, d.URL, "", time.Time{}, "--setup-code", again.res.Code, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "statement timeout 30000 ms (5000 ms set for this database only, which takes precedence), at most 8 connections.")

	privilege := func(table, priv string) bool {
		var ok bool
		require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT has_table_privilege($1, $2, $3)`, role, table, priv).Scan(&ok))
		return ok
	}
	require.True(t, privilege("public.leads", "SELECT"))
	require.False(t, privilege("public.leads", "UPDATE"), "write became read")
	require.False(t, privilege("public.payroll", "SELECT"), "a table no longer listed is revoked")
	require.True(t, agentLogsIn(t, install.credFile, change.res.SetupID), "the password stays")
}

func TestInitSetupCodeUpgrade(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	installed(t, d, dbURL, cfg, "--write", "public.leads")
	latest := guard.LatestVersion()
	d.Exec(t, fmt.Sprintf(`DELETE FROM basalt_meta.schema_version WHERE version = %d`, latest))

	upgrade := remoteDBRun(t, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix)
	require.Equal(t, "UPGRADE", upgrade.res.Kind)
	r := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", upgrade.res.Code, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, fmt.Sprintf("This upgrades Basalt's guard from version %d to %d; no agent changes.", latest-1, latest))
	require.Contains(t, r.stdout, "Check that your agent shows the same fingerprint.")
	require.Contains(t, r.stdout, "record_setup(")
	require.Equal(t, latest-1, installedVersion(t, d), "a dry run runs nothing")

	r = laptopRun(t, d.URL, "", time.Time{}, "--setup-code", upgrade.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, latest, installedVersion(t, d))
	require.Contains(t, r.stdout, "Done. Tell your agent to check its status.")
}

func TestInitSetupCodeUpgradeWithNothingToUpgrade(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	installed(t, d, dbURL, cfg, "--write", "public.leads")
	latest := guard.LatestVersion()
	d.Exec(t, fmt.Sprintf(`DELETE FROM basalt_meta.schema_version WHERE version = %d`, latest))
	upgrade := remoteDBRun(t, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix)
	require.Equal(t, "UPGRADE", upgrade.res.Kind)
	// Someone upgraded the guard since the code was made.
	d.Exec(t, fmt.Sprintf(`INSERT INTO basalt_meta.schema_version (version) VALUES (%d)`, latest))

	r := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", upgrade.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, fmt.Sprintf("basalt: the guard is already at version %d and this code upgrades it to version %d: nothing to upgrade; nothing changed\n",
		latest, latest), r.stderr)
	require.Empty(t, r.stdout)
	setups, err := guard.SetupsFor(context.Background(), d.Admin, uuid.MustParse(upgrade.res.SetupID), "")
	require.NoError(t, err)
	require.Empty(t, setups, "nothing recorded")
}

func TestUpgradeDone(t *testing.T) {
	to := guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	upgrade := setupcode.Payload{Kind: setupcode.KindUpgrade, Guard: setupcode.Guard{From: to - 1, To: to}}
	require.False(t, upgradeDone(upgrade, 0), "no guard: the code installs it")
	require.False(t, upgradeDone(upgrade, to-1))
	require.True(t, upgradeDone(upgrade, to))
	require.True(t, upgradeDone(upgrade, to+1))
	agentCode := setupcode.Payload{Kind: setupcode.KindAgent, Guard: setupcode.Guard{From: to, To: to}}
	require.False(t, upgradeDone(agentCode, to), "only an UPGRADE code is done by the guard alone")
}

func TestSetupRefusedMessage(t *testing.T) {
	t.Parallel()
	l := &laptopSetup{p: setupcode.Payload{Kind: setupcode.KindUpgrade}}
	err := l.refused(&pgconn.PgError{Message: "boom", Detail: "the detail", Hint: "Do this."})
	require.True(t, strings.HasSuffix(err.Error(), ": the detail. Do this. Nothing changed."), err.Error())
	err = l.refused(&pgconn.PgError{Message: "boom", Hint: "Do this"})
	require.True(t, strings.HasSuffix(err.Error(), ": Do this. Nothing changed."), err.Error())
}

func TestSetupPasskeyLabelUpgradeCodeHasNoAgent(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	up := setupcode.Payload{Kind: setupcode.KindUpgrade}
	if got, want := setupPasskeyLabel("", up, "mydb", now), "mydb · 2026-11-14"; got != want {
		t.Fatalf("upgrade default label = %q, want %q", got, want)
	}
	ag := setupcode.Payload{Kind: setupcode.KindAgent, Agent: &setupcode.Agent{Name: "bot"}}
	if got, want := setupPasskeyLabel("", ag, "mydb", now), "mydb · bot · 2026-11-14"; got != want {
		t.Fatalf("agent default label = %q, want %q", got, want)
	}
	if got := setupPasskeyLabel("mine", up, "mydb", now); got != "mine" {
		t.Fatalf("flag label = %q", got)
	}
}
