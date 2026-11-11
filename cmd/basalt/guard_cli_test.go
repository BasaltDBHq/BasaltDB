package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

type result struct {
	code           int
	stdout, stderr string
}

// cli runs basalt with stdin and an environment holding only env.
func cli(t *testing.T, env map[string]string, stdin string, args ...string) result {
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
	code := guardCommands[args[0]](c, args[1:])
	return result{code, stdout.String(), stderr.String()}
}

var guardCommands = map[string]func(*cliIO, []string) int{
	"init": runInit, "log": runLog, "uninstall": runUninstall, "approve": runApprove, "revert": runRevert,
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
		"\"; create them first (the M4 demo: docs/m4/seed.sql)\n", r.stderr)
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
	require.Equal(t, []config.Agent{{Name: "bot", OSUser: "tester", CredentialFile: path}}, cfg.Agents)
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

	// Init again rotates the password: the old credential stops working.
	initAgent(t, d, cfgPath)
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1, "init again replaces the agent entry")
	_, err = pgdial.Connect(ctx, dsn)
	require.Error(t, err)
}

// TestInitWarnsWhenRLSHidesRows: init warns about each agent table where
// row-level security hides every row from the agent role (Supabase can
// turn RLS on for new tables), adds no policy for it, and stays quiet
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
	path := initAgent(t, d, cfgPath)
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

// initOut runs initAgent's init again and returns its stderr.
func initOut(t *testing.T, d *guardtest.DB, configPath string) string {
	t.Helper()
	r := cli(t, map[string]string{envAdminURL: d.URL}, "",
		"init", "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
		"--config", configPath, "--os-user", "tester", "--yes", "--skip-passkey")
	require.Equal(t, exitOK, r.code, r.stderr)
	return r.stderr
}

func TestLogShowsRunChanges(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	path := initAgent(t, d, cfgPath)
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
	require.Contains(t, r.stdout, `UPDATE public.leads (blind write) {"id":4} before=`)
	require.Contains(t, r.stdout, `UPDATE public.lead_owner (cascaded) values hidden`)
	require.NotContains(t, r.stdout, "owner 1")
	require.Empty(t, r.stderr)

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
	require.Empty(t, r.stderr)
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
	require.Empty(t, r.stderr, "a fresh cache has no pin to compare")
	for _, args := range [][]string{{"log"}, {"log", "--full-check"}} {
		r = cli(t, env, "", args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Contains(t, r.stderr, "warning: ledger chain broken at seq ", args)
	}
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
