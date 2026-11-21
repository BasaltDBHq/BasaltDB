package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

type result struct {
	code           int
	stdout, stderr string
}

// cli runs basalt with stdin and an environment holding only env.
func cli(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	return cliOn(t, systemSocketHost(t), env, stdin, args...)
}

// cliOn is cli on host h: pass newFakeHost(t) for a person who is not root,
// whose config dir is short enough for the sockets next to the config.
func cliOn(t *testing.T, h *fakeHost, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cache := t.TempDir()
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string {
			if v, ok := env[k]; ok || k != envCacheDir {
				return v
			}
			return cache
		})
	c.host = h
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

var guardCommands = map[string]func(*cliIO, []string) int{
	"init": runInit, "log": runLog, "uninstall": runUninstall, "approve": runApprove, "revert": runRevert, "passkey": runPasskey, "access": runAccess, "upgrade": runUpgrade,
	"engine": runEngineRecords,
}

// initAgent runs basalt init --yes for agent bot writing public.leads with
// the engine config in a temp dir, and returns the credential file path.
func initAgent(t *testing.T, d *guardtest.DB, configPath string) string {
	t.Helper()
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", configPath, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt engine --config "+configPath)
	require.NotContains(t, r.stderr, "sudo")
	return filepath.Join(filepath.Dir(configPath), "agents", "bot.url")
}

// registerTestPasskey registers a passkey as the admin, so basalt log
// does not warn that none is active.
func registerTestPasskey(t *testing.T, d *guardtest.DB) {
	t.Helper()
	p, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, p.Credential(), "test"))
}

func tempConfig(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "basalt", "engine.json")
}

func TestInitUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"init"},
		{"init", "--agent", "Bad-Name"},
		{"init", "--agent", "bot", "extra"},
		{"init", "--nope"},
		{"log"},
		{"log", "--run", "run_7f3k", "--agent", "bot"},
		{"log", "--sort", "", "--agent", "bot"},
		{"log", "--sort", "newest", "--agent", "bot"},
		{"uninstall", "--prefix", "BAD"},
	} {
		r := cli(t, nil, "", args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
	}
	require.Equal(t, exitOK, cli(t, nil, "", "init", "-h").code)
}

func TestInitNamesEveryMissingTableBeforeChangingAnything(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfg := tempConfig(t)
	var db string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT current_database()`).Scan(&db))

	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads,basalt_demo.leads", "--read", "basalt_demo.lead_notes",
		"--prefix", d.Names.Prefix, "--config", cfg, "--yes", "--skip-passkey")
	require.Equal(t, exitError, r.code)
	require.Equal(t, "basalt: tables basalt_demo.leads, basalt_demo.lead_notes not found in database \""+db+
		"\"; create them first (basalt init --demo creates the sample tables)\n", r.stderr)
	require.Empty(t, r.stdout, "no SQL is planned")
	require.NoFileExists(t, cfg)
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v)

	// One missing table outside the demo: singular, no seed hint.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--read", "nope", "--prefix", d.Names.Prefix, "--config", cfg, "--yes", "--skip-passkey")
	require.Equal(t, exitError, r.code)
	require.Equal(t, "basalt: table public.nope not found in database \""+db+"\"; create it first\n", r.stderr)
}

func TestInitDryRunPrintsRedactedSQL(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfg := tempConfig(t)
	path := filepath.Join(filepath.Dir(cfg), "agents", "bot.url")
	// Admin connection string from the prompt (stdin when not a terminal).
	r := cli(t, nil, d.URL+"\n", "init", "--agent", "bot", "--write", "public.leads",
		"--prefix", d.Names.Prefix, "--config", cfg, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "CREATE SCHEMA IF NOT EXISTS basalt_meta")
	require.Contains(t, r.stdout, "PASSWORD '********'")
	require.Contains(t, r.stderr, "Admin connection string (used once, never stored)")
	require.NoFileExists(t, path)
	require.NoFileExists(t, cfg)
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v)

	// Answering no changes nothing.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "n\n", "init", "--agent", "bot", "--write", "public.leads",
		"--prefix", d.Names.Prefix, "--config", cfg)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "nothing changed")
	v, err = guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v)
}

func TestInitInstallsAndWritesCredential(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), info.Mode().Perm())
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.DefaultSocketDir(runtime.GOOS), cfg.SocketDir)
	require.Equal(t, []config.Agent{{Name: "bot", OSUser: "tester", Store: config.PostgresStore(path), InitArgs: []string{
		"--agent=bot", "--write=public.leads", "--prefix=" + d.Names.Prefix, "--os-user=tester",
	}}}, cfg.Agents)
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "basalt@", "the config holds no credential")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	dsn := strings.TrimSpace(string(b))
	require.NotContains(t, dsn, "postgres:basalt@", "the admin credential is never written")
	require.Contains(t, dsn, d.Names.Prefix+"_agent_bot:")

	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `UPDATE public.leads SET score = 1 WHERE id = 1`)
	code, ok := guard.CodeOf(err)
	require.True(t, ok)
	require.Equal(t, guard.CodeIntentRequired, code)

	// Init again keeps the password: the credential file is untouched and
	// the engine's connection keeps working, with no restart.
	initAgent(t, d, cfgPath)
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1, "init again replaces the agent entry")
	again, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, dsn, strings.TrimSpace(string(again)))
	conn2, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	conn2.Close(ctx)
}

// TestInitWarnsWhenRLSHidesRows: init warns about each agent table where
// row-level security hides every row from the agent role (Supabase can
// turn RLS on for new tables), adds no policy for it with --agent-rls=none, and stays quiet
// once a policy lets the role see rows. basalt log warns the same.
func TestInitWarnsWhenRLSHidesRows(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--read", "public.lead_notes", "--prefix", d.Names.Prefix,
		"--config", cfgPath, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "row-level security", "RLS off")

	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY`)
	path := filepath.Join(filepath.Dir(cfgPath), "agents", "bot.url")
	role := d.Names.Prefix + "_agent_bot"
	require.Contains(t, initOut(t, d, cfgPath),
		"basalt: warning: row-level security is on for public.leads and no policy lets "+role+
			" see rows; the agent will read 0 rows. Add a policy for that role, or disable RLS on the table.")

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(id) FROM public.leads`).Scan(&n))
	require.Zero(t, n, "init does not widen the agent's view")
	lr := cli(t, nil, "", "log", "--credential-file", path)
	require.Equal(t, exitOK, lr.code, lr.stderr)
	require.Contains(t, lr.stderr, "warning: row-level security is on for public.leads and no policy lets this agent see rows")

	d.Exec(t, `CREATE POLICY bot ON public.leads FOR SELECT TO `+role+` USING (true)`)
	require.NotContains(t, initOut(t, d, cfgPath), "row-level security")
}

// agentRows counts the rows of table the agent's credential file sees.
func agentRows(t *testing.T, credFile, table string) int {
	t.Helper()
	b, err := os.ReadFile(credFile)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)
	var n int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(id) FROM `+table).Scan(&n))
	return n
}

// agentPolicyCount counts the policies named after the agent role.
func agentPolicyCount(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(1)::int FROM pg_policy WHERE polname = $1`,
		d.Names.Prefix+"_agent_bot").Scan(&n))
	return n
}

// TestInitAsksBeforeLettingTheAgentSeeRLSRows: at a terminal init asks once
// per agent table RLS hides (row count shown, default no); yes adds the
// agent policy and the agent sees the rows; no leaves 0 rows and the
// warning; re-init asks only about new blind tables; without a terminal
// with --yes every table is added unless --agent-rls=none or a list; tables not
// granted to the agent are never touched (decision "Agent RLS", Nov 12).
func TestInitAsksBeforeLettingTheAgentSeeRLSRows(t *testing.T) {
	t.Parallel()
	question := func(table string, rows int) string {
		return fmt.Sprintf("public.%s hides its rows with row-level security. Let bot see all %d rows of this table? [y/N]", table, rows)
	}
	setup := func(t *testing.T) (*guardtest.DB, string, []string) {
		t.Helper()
		d := guardtest.New(t).WithDemo(t)
		d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
			ALTER TABLE public.lead_notes ENABLE ROW LEVEL SECURITY;
			ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY`)
		cfg := tempConfig(t)
		return d, filepath.Join(filepath.Dir(cfg), "agents", "bot.url"), []string{"--config", cfg, "--os-user", "tester"}
	}

	t.Run("yes and no at a terminal", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		h := newFakeHost(t)
		// Answers: yes for leads, default (no) for lead_notes, run the SQL.
		r := initRun(t, d, h, "linux", true, "y\n\ny\n", append(args, "--read", "public.lead_notes", "--show-sql")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Contains(t, r.stderr, question("leads", 200))
		require.Contains(t, r.stderr, question("lead_notes", 60))
		require.NotContains(t, r.stderr, "payroll")
		require.Contains(t, r.stdout, "CREATE POLICY "+d.Names.Prefix+"_agent_bot ON public.leads AS PERMISSIVE FOR ALL")
		require.NotContains(t, r.stdout, "ON public.lead_notes AS PERMISSIVE")
		require.NotContains(t, r.stderr, "row-level security is on for public.leads")
		require.Contains(t, r.stderr, "row-level security is on for public.lead_notes and no policy lets")
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
		require.Zero(t, agentRows(t, cred, "public.lead_notes"))
		require.Equal(t, 1, agentPolicyCount(t, d))

		// Re-init asks only about lead_notes, which is still blind.
		r = initRun(t, d, h, "linux", true, "y\ny\n", append(args, "--read", "public.lead_notes")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, question("leads", 200))
		require.Contains(t, r.stderr, question("lead_notes", 60))
		require.Equal(t, 60, agentRows(t, cred, "public.lead_notes"))
		require.Equal(t, 2, agentPolicyCount(t, d))

		// --agent-rls=none skips the question.
		d.Exec(t, `ALTER TABLE public.note_tags ENABLE ROW LEVEL SECURITY`)
		r = initRun(t, d, h, "linux", true, "y\n", append(args, "--read", "public.lead_notes,public.note_tags", "--agent-rls", "none")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "hides its rows")
		require.Contains(t, r.stderr, "row-level security is on for public.note_tags and no policy lets")

		r = cli(t, map[string]string{envAdminURL: d.URL}, "", "uninstall", "--prefix", d.Names.Prefix, "--yes")
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Zero(t, agentPolicyCount(t, d))
	})

	t.Run("without a terminal or with --yes", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		h := newFakeHost(t)
		r := initRun(t, d, h, "linux", false, "none\ny\n", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "hides its rows")
		require.Contains(t, r.stderr, "row-level security is on for public.leads and no policy lets")
		// --yes alone and --yes --agent-rls=none: none adds nothing, prints no line.
		r = initRun(t, d, h, "linux", true, "", append(args, "--yes", "--agent-rls", "none")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "hides its rows")
		require.NotContains(t, r.stderr, "can see all rows of")
		require.Zero(t, agentRows(t, cred, "public.leads"))
		require.Zero(t, agentPolicyCount(t, d))

		// --dry-run shows the policies in its SQL and changes nothing.
		r = initRun(t, d, h, "linux", true, "", append(args, "--dry-run")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Contains(t, r.stdout, "CREATE POLICY "+d.Names.Prefix+"_agent_bot ON public.leads AS PERMISSIVE FOR ALL")
		require.Contains(t, r.stderr, "bot can see all rows of public.leads")
		require.Zero(t, agentPolicyCount(t, d))

		// --yes alone adds every table and says so.
		r = initRun(t, d, h, "linux", true, "", append(args, "--yes")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Contains(t, r.stderr, "bot can see all rows of public.leads")
		require.Contains(t, r.stderr, "--agent-rls=none")
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
		require.Equal(t, 1, agentPolicyCount(t, d))

		r = initRun(t, d, h, "linux", false, "", append(args, "--yes", "--agent-rls", "all-rows")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "row-level security is on")
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
		require.Equal(t, 1, agentPolicyCount(t, d))
		var payroll int
		require.NoError(t, d.Admin.QueryRow(context.Background(),
			`SELECT count(1)::int FROM pg_policy WHERE polrelid = 'public.payroll'::regclass`).Scan(&payroll))
		require.Zero(t, payroll, "a table not granted to the agent is never touched")
	})

	t.Run("a table the agent was not given", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		h := newFakeHost(t)
		r := initRun(t, d, h, "linux", false, "", append(args, "--yes", "--agent-rls", "none")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		// The agent role can SELECT payroll through PUBLIC; RLS is the only
		// barrier, and payroll is in neither of its lists.
		d.Exec(t, `GRANT SELECT ON public.payroll TO PUBLIC`)
		payrollPolicies := func() int {
			var n int
			require.NoError(t, d.Admin.QueryRow(context.Background(),
				`SELECT count(1)::int FROM pg_policy WHERE polrelid = 'public.payroll'::regclass`).Scan(&n))
			return n
		}

		r = initRun(t, d, h, "linux", false, "", append(args, "--agent-rls", "public.payroll")...)
		require.Equal(t, exitUsage, r.code, r.stderr)
		require.Contains(t, r.stderr, "public.payroll")

		r = initRun(t, d, h, "linux", true, "", append(args, "--dry-run")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stdout, "ON public.payroll")
		require.NotContains(t, r.stderr, "payroll")

		// An empty piped line means all: all of the agent's tables only.
		r = initRun(t, d, h, "linux", false, "\ny\n", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "payroll")
		require.Zero(t, payrollPolicies())

		r = initRun(t, d, h, "linux", true, "", append(args, "--yes")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "payroll")
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
		require.Zero(t, agentRows(t, cred, "public.payroll"))
		require.Zero(t, payrollPolicies())
	})

	t.Run("a list on the flag", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		h := newFakeHost(t)
		args = append(args, "--read", "public.lead_notes")
		// An unknown entry is a usage error before anything is written.
		r := initRun(t, d, h, "linux", false, "", append(args, "--agent-rls", "public.leads,public.nope")...)
		require.Equal(t, exitUsage, r.code, r.stderr)
		require.Contains(t, r.stderr, "public.nope")
		require.Zero(t, agentPolicyCount(t, d))
		// Only the listed table gets a policy; the other warns.
		r = initRun(t, d, h, "linux", false, "y\n", append(args, "--agent-rls", "public.leads")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "hides its rows")
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
		require.Zero(t, agentRows(t, cred, "public.lead_notes"))
		require.Equal(t, 1, agentPolicyCount(t, d))
		// schema.* covers the rest, and it applies with --yes too.
		r = initRun(t, d, h, "linux", false, "", append(args, "--yes", "--agent-rls", "public.*")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Equal(t, 60, agentRows(t, cred, "public.lead_notes"))
		require.Equal(t, 2, agentPolicyCount(t, d))
	})

	t.Run("one line on piped input", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		h := newFakeHost(t)
		args = append(args, "--read", "public.lead_notes")
		// The list is printed on stderr, grouped by schema, with row counts.
		r := initRun(t, d, h, "linux", false, "bad answer\n", args...)
		require.Equal(t, exitUsage, r.code, r.stderr)
		require.Contains(t, r.stderr, "public (2 tables, 260 rows)")
		require.Contains(t, r.stderr, "public.leads  200 rows")
		require.Contains(t, r.stderr, "--agent-rls form")
		require.Zero(t, agentPolicyCount(t, d))
		r = initRun(t, d, h, "linux", false, "public.nope\n", args...)
		require.Equal(t, exitUsage, r.code, r.stderr)
		require.Zero(t, agentPolicyCount(t, d))
		// A list.
		r = initRun(t, d, h, "linux", false, "public.leads\ny\n", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Equal(t, 1, agentPolicyCount(t, d))
		// An empty line is all (the default).
		r = initRun(t, d, h, "linux", false, "\ny\n", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Equal(t, 60, agentRows(t, cred, "public.lead_notes"))
		require.Equal(t, 2, agentPolicyCount(t, d))
	})

	t.Run("end of input is all", func(t *testing.T) {
		t.Parallel()
		d, cred, args := setup(t)
		// No line at all for the question: all. --yes asks nothing else.
		r := initRun(t, d, newFakeHost(t), "linux", false, "", append(args, "--agent-rls", "ask", "--dry-run")...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Zero(t, agentPolicyCount(t, d), "a dry run changes nothing")
		r = initRun(t, d, newFakeHost(t), "linux", false, "\ny\n", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Equal(t, 200, agentRows(t, cred, "public.leads"))
	})

	t.Run("bad flag", func(t *testing.T) {
		t.Parallel()
		r := cli(t, nil, "", "init", "--agent", "bot", "--agent-rls", "some")
		require.Equal(t, exitUsage, r.code)
		require.Contains(t, r.stderr, "must be ask, all-rows, none or a list")
		r = cli(t, nil, "", "init", "--agent", "bot", "--agent-rls", "ALL_ROWS")
		require.Equal(t, exitUsage, r.code, "flag values are lowercase kebab-case")
	})
}

// initOut runs initAgent's init again and returns its stderr.
func initOut(t *testing.T, d *guardtest.DB, configPath string) string {
	t.Helper()
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", configPath, "--os-user", "tester", "--yes", "--agent-rls", "none", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	return r.stderr
}

func TestLogShowsRunChanges(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
	registerTestPasskey(t, d)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)

	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Merge duplicate case reports"}
	require.NoError(t, guard.StartRun(ctx, conn, in))
	require.NoError(t, guardtest.Guarded(ctx, conn, in, `UPDATE public.leads SET status = 'merged' WHERE id = 4`))
	require.NoError(t, guardtest.Guarded(ctx, conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))

	r := cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath, "--run", in.RunID.String())
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, `"Merge duplicate case reports"`)
	require.Contains(t, r.stdout, `UPDATE public.leads (blind write) {"id":4} status open -> merged`+"\n", "compact: key and changed columns")
	require.Contains(t, r.stdout, `id 101 -> 9101`)
	require.Contains(t, r.stdout, `UPDATE public.lead_owner (cascaded) values hidden`)
	require.NotContains(t, r.stdout, "before=")
	require.NotContains(t, r.stdout, "owner 1")
	require.Empty(t, withoutPII(r.stderr))

	r = cli(t, nil, "", "log", "--agent", "bot", "--config", cfgPath, "--run", in.RunID.String(), "--full")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, `UPDATE public.leads (blind write) {"id":4} before=`)

	r = cli(t, map[string]string{envAgentURL: strings.TrimSpace(string(b))}, "", "log", "--json", "--limit", "1", "--sort", "id")
	require.Equal(t, exitOK, r.code, r.stderr)
	var recs []ledger.Record
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &recs))
	require.Len(t, recs, 1)
	require.Equal(t, "APPLIED", recs[0].Status)
	require.Equal(t, "AGENT", recs[0].Actor.Kind)
	require.Equal(t, in.RunID.String(), recs[0].Actor.RunID)
	require.Equal(t, "merged", recs[0].RowChanges[0].After["status"])
	require.Contains(t, r.stderr, "next cursor: ")
}

func TestLogWarns(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	path := initAgent(t, d, tempConfig(t))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, strings.TrimSpace(string(b)))
	require.NoError(t, err)
	defer conn.Close(ctx)
	require.NoError(t, guard.Heartbeat(ctx, conn, nil))

	d.Exec(t, `UPDATE basalt_meta.ledger SET detail = '{}' WHERE seq = 1`)
	d.Exec(t, `CREATE TABLE public.lead_files (id bigint PRIMARY KEY, lead_id bigint REFERENCES public.leads ON DELETE CASCADE)`)

	var stdout, stderr bytes.Buffer
	cache := t.TempDir()
	c := newIO(ctx, stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return map[string]string{envCacheDir: cache}[k] })
	c.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	require.Equal(t, exitOK, runLog(c, []string{"--credential-file", path}), stderr.String())
	require.Contains(t, stderr.String(), "warning: ledger chain broken at seq 1")
	require.Contains(t, stderr.String(), "warning: table lead_files is not guarded")
	require.Contains(t, stderr.String(), "warning: no engine heartbeat since")
}

func TestLogVerifiesFromItsPin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	path := initAgent(t, d, tempConfig(t))
	registerTestPasskey(t, d)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	dsn := strings.TrimSpace(string(b))
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	require.NoError(t, guard.Heartbeat(ctx, conn, nil))
	require.NoError(t, guard.Heartbeat(ctx, conn, nil))

	cache := t.TempDir()
	env := map[string]string{envAgentURL: dsn, envCacheDir: cache}
	r := cli(t, env, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, withoutPII(r.stderr))
	pins, err := os.ReadDir(filepath.Join(cache, "ledger-pins"))
	require.NoError(t, err)
	require.Len(t, pins, 1, "the verified head is pinned")

	// History rewritten consistently: the full check alone passes, the
	// pinned head does not.
	d.Exec(t, `DO $$
	DECLARE prev bytea := '\x0000000000000000000000000000000000000000000000000000000000000000'; l basalt_meta.ledger;
	BEGIN
		UPDATE basalt_meta.ledger SET detail = '{"forged": true}' WHERE seq = 1;
		FOR l IN SELECT * FROM basalt_meta.ledger ORDER BY seq LOOP
			UPDATE basalt_meta.ledger SET prev_hash = prev, hash = sha256(prev || basalt_meta._canonical(l))
			 WHERE seq = l.seq RETURNING hash INTO prev;
		END LOOP;
		UPDATE basalt_meta.chain_head SET hash = prev WHERE id;
	END $$`)
	r = cli(t, map[string]string{envAgentURL: dsn}, "", "log")
	require.Empty(t, withoutPII(r.stderr), "a fresh cache has no pin to compare")
	for _, args := range [][]string{{"log"}, {"log", "--full-check"}} {
		r = cli(t, env, "", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Contains(t, r.stderr, "warning: ledger chain broken at seq ", args)
	}
}

// logPin is the one pin basalt log keeps in cache.
func logPin(t *testing.T, cache string) (chainpin.File, string) {
	t.Helper()
	dir := filepath.Join(cache, "ledger-pins")
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	return chainpin.File{Dir: dir}, strings.TrimSuffix(files[0].Name(), ".head.json")
}

// A reinstall over basalt log's pin is reported in the new ledger and shown
// on every run as the reinstall notice, never as a broken chain; the pin
// keeps a copy of the report.
func TestLogShowsAReinstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	registerTestPasskey(t, d)
	ctx := context.Background()
	require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
	cache := t.TempDir()
	r := cli(t, map[string]string{envAgentURL: a.URL, envCacheDir: cache}, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	pins, name := logPin(t, cache)
	old, _, err := pins.Load(name)
	require.NoError(t, err)

	require.NoError(t, a.Conn.Close(ctx))
	require.NoError(t, guard.Uninstall(ctx, d.Admin, d.Names))
	b := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	registerTestPasskey(t, d)
	env := map[string]string{envAgentURL: b.URL, envCacheDir: cache}
	notice := fmt.Sprintf("Previous ledger ended at entry %d (hash %s), as reported with the credential of %s. "+
		"If nobody on your team reinstalled Basalt, treat this as tampering.\n", old.Head.Seq, hex.EncodeToString(old.Head.Hash), b.Role)
	for range 2 {
		r = cli(t, env, "", "log")
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "chain broken")
		require.Contains(t, r.stderr, "This database's ledger was reinstalled on ")
		require.Contains(t, r.stderr, notice)
	}
	now, _, err := pins.Load(name)
	require.NoError(t, err)
	require.NotEqual(t, old.Install, now.Install)
	require.Len(t, now.SetAside, 1)
	require.Equal(t, old.Head.Seq, now.SetAside[0].PinnedSeq)
}

// The same ledger under another install id (the installs row deleted and
// written again by basalt init) moves basalt log's pin with a warning on
// stderr, and records nothing.
func TestLogMovesItsPinToANewInstallOfTheSameLedger(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	registerTestPasskey(t, d)
	cache := t.TempDir()
	env := map[string]string{envAgentURL: a.URL, envCacheDir: cache}
	r := cli(t, env, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	pins, name := logPin(t, cache)
	p, _, err := pins.Load(name)
	require.NoError(t, err)
	current := p.Install
	p.Install = uuid.New()
	require.NoError(t, pins.Save(name, p))

	r = cli(t, env, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, fmt.Sprintf("warning: the guard was installed again over the same ledger (guard install %s is now %s)",
		p.Install, current))
	require.NotContains(t, r.stderr, "reinstalled")
	require.NotContains(t, r.stderr, "chain broken")
	now, _, err := pins.Load(name)
	require.NoError(t, err)
	require.Equal(t, current, now.Install)
}

// The quickstart path: the Postgres container removed and started again
// from the same image, and basalt init run again with the same database
// and role. basalt_meta has the same schema oid as before. basalt log
// reports its old pin as a reinstall and shows the notice, never a broken
// chain, on every run and with --full-check; a rewrite of the new ledger
// is still caught.
func TestLogAfterTheDatabaseIsRecreated(t *testing.T) {
	t.Parallel()
	d := guardtest.NewRecreatable(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	registerTestPasskey(t, d)
	ctx := context.Background()
	require.NoError(t, guard.Heartbeat(ctx, a.Conn, nil))
	cache := t.TempDir()
	r := cli(t, map[string]string{envAgentURL: a.URL, envCacheDir: cache}, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	pins, name := logPin(t, cache)
	old, _, err := pins.Load(name)
	require.NoError(t, err)
	require.Positive(t, old.Head.Seq)

	d.Recreate(t)
	d.WithDemo(t)
	b := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	registerTestPasskey(t, d)
	env := map[string]string{envAgentURL: b.URL, envCacheDir: cache}
	for _, args := range [][]string{{"log"}, {"log"}, {"log", "--full-check"}} {
		r = cli(t, env, "", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.NotContains(t, r.stderr, "chain broken", args)
		require.Contains(t, r.stderr, "This database's ledger was reinstalled on ", args)
	}
	_, again := logPin(t, cache)
	require.Equal(t, name, again, "the same database and role: the same pin")
	now, _, err := pins.Load(name)
	require.NoError(t, err)
	require.NotEqual(t, old.Install, now.Install)
	require.Len(t, now.SetAside, 1)

	d.Exec(t, `UPDATE basalt_meta.ledger SET hash = sha256(hash) WHERE seq = $1`, now.Head.Seq)
	r = cli(t, env, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, fmt.Sprintf("warning: ledger chain broken at seq %d", now.Head.Seq))
}

func TestLogShowsTheDeadManRow(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	path := initAgent(t, d, tempConfig(t))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	dsn := strings.TrimSpace(string(b))
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	require.NoError(t, guard.RecordEvent(ctx, conn, guard.EventDeadMan,
		map[string]any{"lastHeartbeat": "2026-11-01T00:00:00Z", "silentHours": 200}))
	require.NoError(t, guard.Heartbeat(ctx, conn, nil))

	r := cli(t, map[string]string{envAgentURL: dsn}, "", "log")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "warning: the engine was silent for 200 hours (last heartbeat 2026-11-01T00:00:00Z)")
}

func TestUninstallRemovesEverything(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	initAgent(t, d, tempConfig(t))
	r := cli(t, map[string]string{envAdminURL: d.URL}, "y\n", "uninstall", "--prefix", d.Names.Prefix)
	require.Equal(t, exitOK, r.code, r.stderr)
	var schemas, roles int
	ctx := context.Background()
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_namespace WHERE nspname = 'basalt_meta'`).Scan(&schemas))
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_roles WHERE rolname LIKE $1`, d.Names.Prefix+`\_%`).Scan(&roles))
	require.Zero(t, schemas)
	require.Zero(t, roles)
}

func TestHelpSaysOneEngineServesManyAgents(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"init", "-h"}} {
		code, stdout, stderr := runArgs(args...)
		require.Equal(t, exitOK, code, stderr)
		out := stdout + stderr
		for _, want := range []string{"One engine serves many agents", "one database", "basalt init --remote --agent NAME"} {
			require.Contains(t, out, want, args)
		}
	}
}

func TestInitOperatedByAgentWithTheAdminCredential(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	config := tempConfig(t)
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "x1", "--write", "public.leads", "--prefix", d.Names.Prefix, "--operated-by", "agent",
		"--config", config, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err := os.ReadFile(config)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"operatedBy": "AGENT"`)
	require.Contains(t, string(raw), "https://portal.basaltvault.app")
	require.Contains(t, string(raw), "--operated-by=agent")

	// A local passkey origin does not fit an engine the bot operates.
	r = cli(t, nil, "", "init", "--agent", "x2", "--operated-by", "agent", "--passkey-origin", "http://localhost:8787")
	require.Equal(t, exitUsage, r.code, r.stderr)
	require.Contains(t, r.stderr, "portal")

	// The default leaves operatedBy alone.
	config = tempConfig(t)
	initAgent(t, d, config)
	raw, err = os.ReadFile(config)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "operatedBy")
}

// --dev-local-pages lets the owner try an agent-operated engine on local
// pages; nothing else gets a local or foreign origin (CONTRACT.md, Page
// origins).
func TestInitDevLocalPages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"without an agent-operated engine", []string{"--dev-local-pages"}, "only for --operated-by=agent"},
		{"with the portal", []string{"--operated-by", "agent", "--dev-local-pages", "--passkey-origin", links.Portal}, "needs a local --passkey-origin"},
		{"pages.dev, person", []string{"--passkey-origin", "https://basalt-portal.pages.dev"}, "--passkey-origin"},
		{"pages.dev, agent", []string{"--operated-by", "agent", "--passkey-origin", "https://basalt-portal.pages.dev"}, "portal"},
		{"pages.dev, dev pages", []string{"--operated-by", "agent", "--dev-local-pages", "--passkey-origin", "https://basalt-portal.pages.dev"}, "--passkey-origin"},
	} {
		r := cli(t, nil, "", append([]string{"init", "--agent", "x2"}, tc.args...)...)
		require.Equal(t, exitUsage, r.code, tc.name+": "+r.stderr)
		require.Contains(t, r.stderr, tc.want, tc.name)
	}

	d := guardtest.New(t).WithDemo(t)
	config := tempConfig(t)
	base := []string{
		"init", "--agent", "x1", "--write", "public.leads", "--prefix", d.Names.Prefix, "--operated-by", "agent",
		"--config", config, "--os-user", "tester", "--yes", "--skip-passkey",
	}
	r := cli(t, map[string]string{envAdminURL: d.URL}, "", append(slices.Clone(base), "--dev-local-pages")...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "DEV_LOCAL_PAGES: these pages are on the agent's machine; never use this with a bot you do not control")
	var cfg struct {
		PagesURL      string `json:"pagesUrl"`
		DevLocalPages bool   `json:"devLocalPages"`
		Vault         string `json:"vault"`
		Agents        []struct {
			InitArgs []string `json:"initArgs"`
		} `json:"agents"`
	}
	raw, err := os.ReadFile(config)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &cfg))
	require.True(t, cfg.DevLocalPages)
	require.Equal(t, links.DefaultLocal, cfg.PagesURL, "the default origin with --dev-local-pages is local")
	require.NotEqual(t, "ON", cfg.Vault, "the Vault carries portal links only")
	require.Contains(t, cfg.Agents[0].InitArgs, "--dev-local-pages=true")

	// An explicit local origin, as the contract's command gives it.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "", append(slices.Clone(base), "--dev-local-pages", "--passkey-origin", "http://localhost:9000")...)
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err = os.ReadFile(config)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"pagesUrl": "http://localhost:9000"`)
	require.Contains(t, string(raw), `"devLocalPages": true`)

	// Init again without the flag moves the engine to the portal.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "", base...)
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err = os.ReadFile(config)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "devLocalPages")
	require.Contains(t, string(raw), links.Portal)
}

func TestRelyingPartyAcceptsThePortal(t *testing.T) {
	t.Parallel()
	rp, err := relyingParty(links.Portal)
	require.NoError(t, err)
	require.Equal(t, passkey.Production, rp)
}

func TestInitOperatedByAgentWithAnExplicitPortalOrigin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	config := tempConfig(t)
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "x1", "--write", "public.leads", "--prefix", d.Names.Prefix, "--operated-by", "agent",
		"--passkey-origin", links.Portal, "--config", config, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err := os.ReadFile(config)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"operatedBy": "AGENT"`)
	// The saved flags round-trip into the commands the CLI prints.
	var cfg struct {
		Agents []struct {
			InitArgs []string `json:"initArgs"`
		} `json:"agents"`
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))
	_, err = agent.NewCommands("x1", config, "linux")
	require.NoError(t, err)

	// Switched back by an explicit --operated-by person.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "x1", "--write", "public.leads", "--prefix", d.Names.Prefix, "--operated-by", "person",
		"--config", config, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err = os.ReadFile(config)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"operatedBy": "PERSON"`)
}

func TestInitRerunsAfterAFailedPasskeyPaste(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	config := tempConfig(t)
	args := slices.Clip([]string{
		"init", "--agent", "bot_a", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", config, "--os-user", "tester", "--yes",
	})
	r := cli(t, map[string]string{envAdminURL: d.URL}, "not a passkey code\n", args...)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "held writes cannot be approved until you register one (run basalt init again)")
	// The credential and the config were written before the failure was reported.
	require.FileExists(t, filepath.Join(filepath.Dir(config), "agents", "bot_a.url"))
	require.FileExists(t, config)

	// The rerun the message asks for does not refuse the role that exists.
	r = cli(t, map[string]string{envAdminURL: d.URL}, "", slices.Concat(args, []string{"--skip-passkey"})...)
	require.Equal(t, exitOK, r.code, r.stderr)
}

// A table the guard cannot key (no primary key) fails the install; init says
// which table and how to fix it, not only "NOT_ALLOWED (SQLSTATE BS007)".
func TestInitShowsTheGuardsDetailAndHint(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.nopk (a int, b text)`)
	cfg := tempConfig(t)

	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads,public.nopk",
		"--prefix", d.Names.Prefix, "--config", cfg, "--yes", "--skip-passkey", "--no-service")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "NOT_ALLOWED")
	require.Contains(t, r.stderr, "table public.nopk has no primary key; the guard keys ledger rows by it.")
	require.Contains(t, r.stderr, "add a primary key, or revoke the agent's write privileges on it.")
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Zero(t, v, "the transaction rolled back")
}

// runGuard runs args[0] on c with the path flags moved into c.paths.
func runGuard(c *cliIO, args []string) int {
	cmd := guardCommands[args[0]]
	return cmd(c, takePathFlags(c, cmd, args[1:]))
}
