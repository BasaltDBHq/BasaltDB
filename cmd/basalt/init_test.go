package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

func TestForegroundNext(t *testing.T) {
	t.Parallel()
	f := initFlags{
		agent: "bot", configPath: "/home/dev/basalt/engine.json", socketDir: "/home/dev/basalt/run", osUser: "iman",
	}
	require.Equal(t, `next, start the engine; it runs in the foreground as you (same-user mode: writes are guarded, but your OS user can read the credential):
  basalt engine --config /home/dev/basalt/engine.json
then add this MCP server to the agent's client, running as OS user iman (docs/mcp-clients.md):
  basalt mcp --agent bot --socket-dir /home/dev/basalt/run --config /home/dev/basalt/engine.json
`, foregroundNext(f, "linux", newFakeHost(t)))

	f.configPath, f.socketDir = "/Users/me/Library/Application Support/basalt/engine.json", config.DefaultSocketDir("darwin")
	h := newFakeHost(t)
	require.Contains(t, foregroundNext(f, "darwin", h), "basalt engine --config '/Users/me/Library/Application Support/basalt/engine.json'")
	require.True(t, strings.HasSuffix(foregroundNext(f, "darwin", h), "  basalt mcp --agent bot --config '/Users/me/Library/Application Support/basalt/engine.json'\n"),
		"the default socket dir needs no flag, a config basalt mcp would not find does")
}

// With the config where basalt mcp looks with no --config, the line is the
// one it always was.
func TestInitMCPLineDefaultConfigUnchanged(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	f := initFlags{agent: "bot", osUser: "iman", configPath: config.DefaultPath("linux"), socketDir: config.DefaultSocketDir("linux")}
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot"}, mcpArgs(f, "linux", "basalt", h))

	// The per-user config init left, found by basalt mcp itself.
	user := filepath.Join(h.configDir, perUserDirName, "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(user), 0o700))
	require.NoError(t, os.WriteFile(user, []byte("{}"), 0o600))
	f.configPath = user
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot"}, mcpArgs(f, "linux", "basalt", h))

	// Any other config is named, as an absolute path.
	f.configPath = "/workspace/basalt/engine.json"
	f.socketDir = "/workspace/basalt/run"
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot", "--socket-dir", "/workspace/basalt/run", "--config", "/workspace/basalt/engine.json"}, mcpArgs(f, "linux", "basalt", h))
}

// root looks only at the system path.
func TestMCPConfigArgsAsRoot(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.euid = 0
	require.Nil(t, mcpConfigArgs(config.DefaultPath("linux"), "linux", h))
	require.Equal(t, []string{"--config", "/srv/b/engine.json"}, mcpConfigArgs("/srv/b/engine.json", "linux", h))
}

func TestServiceInstallArgsKeepTheCredentialOffTheCommandLine(t *testing.T) {
	t.Parallel()
	f := initFlags{agent: "bot", configPath: "/etc/basalt/engine.json", engineUser: "basalt", osUser: "iman"}
	require.Equal(t, []string{
		"/usr/local/bin/basalt", "service", "install", "--config", "/etc/basalt/engine.json", "--user", "basalt",
		"--agent", "bot", "--os-user", "iman", "--credential-stdin",
	}, serviceInstallArgs(f, "/usr/local/bin/basalt"))
	f.passkeyOrigin = "http://localhost:8787"
	require.Contains(t, serviceInstallArgs(f, "/b"), "--pages-url")
	require.Contains(t, serviceInstallArgs(f, "/b"), "http://localhost:8787")
}

func TestEngineSettings(t *testing.T) {
	t.Parallel()
	// The platform default config keeps the default state directory and page.
	f := initFlags{configPath: "/etc/basalt/engine.json", socketDir: "/run/basalt"}
	require.Equal(t, config.Settings{SocketDir: "/run/basalt", Mode: config.ModeSameUser}, engineSettings(f, "linux"))

	// A per-user config keeps its state next to it; a development passkey
	// origin serves the approval page.
	f = initFlags{
		configPath: "/home/iman/basalt/engine.json", socketDir: "/home/iman/basalt/run",
		passkeyOrigin: "http://localhost:8787",
	}
	require.Equal(t, config.Settings{
		SocketDir: "/home/iman/basalt/run", StateDir: "/home/iman/basalt/state",
		PagesURL: "http://localhost:8787", Mode: config.ModeSameUser,
	}, engineSettings(f, "linux"))
}

func TestServiceInstallArgsKeepTheCredentialFileWhenThePasswordIsKept(t *testing.T) {
	t.Parallel()
	f := initFlags{
		agent: "bot", configPath: "/etc/basalt/engine.json", engineUser: "basalt", osUser: "iman",
		keepCredential: true, initArgs: []string{"--agent=bot", "--os-user=iman"},
	}
	args := serviceInstallArgs(f, "/b")
	require.Equal(t, []string{"--init-arg", "--agent=bot", "--init-arg", "--os-user=iman", "--keep-credential"}, args[len(args)-5:])
	require.NotContains(t, args, "--credential-stdin")
}

func TestInitRefusesAnUnusableAdminStringBeforeConnecting(t *testing.T) {
	t.Parallel()
	for admin, want := range map[string]error{
		"host=db user=admin password=ADMINSECRET dbname=app":         guard.ErrAdminURLForm,
		"postgres://admin:ADMINSECRET@%2Fvar%2Frun%2Fpostgresql/app": guard.ErrAdminURLParse,
	} {
		var stdout, stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
			func(k string) string {
				if k == envAdminURL {
					return admin
				}
				return ""
			})
		c.dial = func(context.Context, string) (*pgx.Conn, error) {
			t.Errorf("init connected with %q", admin)
			return nil, context.Canceled
		}
		code := runInit(c, []string{"--agent", "bot", "--yes", "--no-service", "--config", t.TempDir() + "/engine.json"})
		require.Equal(t, exitError, code, stderr.String())
		require.Contains(t, stderr.String(), want.Error())
		require.NotContains(t, stderr.String(), "ADMINSECRET")
	}
}

func TestInitRecordsThePerson(t *testing.T) {
	t.Parallel()
	h := &fakeHost{euid: 501}
	c := &cliIO{getenv: func(string) string { return "" }, host: h}

	uids, err := persons(c, initFlags{})
	require.NoError(t, err)
	require.Equal(t, []uint32{501}, uids, "the person running init")

	uids, err = persons(c, initFlags{personUIDs: []uint32{502, 503}})
	require.NoError(t, err)
	require.Equal(t, []uint32{502, 503}, uids, "--person-uid wins")

	h.euid = 0
	c.getenv = func(k string) string { return map[string]string{envSudoUID: "504"}[k] }
	uids, err = persons(c, initFlags{})
	require.NoError(t, err)
	require.Equal(t, []uint32{504}, uids, "init under sudo: the user who ran sudo")

	c.getenv = func(string) string { return "" }
	_, err = persons(c, initFlags{})
	require.ErrorIs(t, err, errNoPerson, "a root login without --person-uid installs no service")
	_, err = persons(c, initFlags{personUIDs: []uint32{0}})
	require.ErrorContains(t, err, "is root")

	f := initFlags{agent: "bot", configPath: "/etc/basalt/engine.json", engineUser: "basalt", osUser: "iman", personUIDs: []uint32{501, 502}}
	args := serviceInstallArgs(f, "/b")
	require.Equal(t, []string{"--person-uid", "501", "--person-uid", "502", "--credential-stdin"}, args[len(args)-5:])
	require.NotContains(t, f.savedArgs("linux"), "--person-uid=501", "a one-shot flag, not saved")
}

func TestInitSQLSummary(t *testing.T) {
	t.Parallel()
	f := initFlags{spec: guard.AgentSpec{Write: []string{"public.leads"}, Read: []string{"public.notes"}}}
	got := initSQLSummary(f, "basalt_agent_bot", false)
	require.Contains(t, got, "basalt: this setup SQL will:")
	require.Contains(t, got, "- install or upgrade the guard (basalt_meta)")
	require.Contains(t, got, "- create the agent role basalt_agent_bot")
	require.Contains(t, got, "- let the agent write public.leads")
	require.Contains(t, got, "- let the agent read public.notes")
	require.Contains(t, got, "Pass --show-sql to print the SQL (passwords redacted).")
	require.NotContains(t, got, "CREATE ")
	require.LessOrEqual(t, strings.Count(got, "\n"), 24)

	demo := initSQLSummary(initFlags{}, "basalt_agent_demo_bot", true)
	require.Contains(t, demo, "- create the sample schema basalt_demo")
	require.Contains(t, demo, "- create the agent role basalt_agent_demo_bot")

	keep := initSQLSummary(initFlags{keepCredential: true}, "basalt_agent_bot", false)
	require.Contains(t, keep, "- keep the existing agent role basalt_agent_bot (its password is unchanged)")

	rotate := initSQLSummary(initFlags{rotated: true}, "basalt_agent_bot", false)
	require.Contains(t, rotate, "- set a new password for the existing agent role basalt_agent_bot")
}

func TestPrintInitSQL(t *testing.T) {
	t.Parallel()
	script := guard.Script{Statements: []guard.Statement{{Shown: "CREATE SCHEMA IF NOT EXISTS basalt_meta;\n"}}}
	var stdout strings.Builder
	c := &cliIO{stdout: &stdout}
	printInitSQL(c, initFlags{}, "basalt_agent_bot", "", script)
	require.NotContains(t, stdout.String(), "CREATE SCHEMA")
	require.Contains(t, stdout.String(), "Pass --show-sql")

	stdout.Reset()
	printInitSQL(c, initFlags{showSQL: true}, "basalt_agent_bot", "-- demo --\n", script)
	require.Equal(t, "-- demo --\nCREATE SCHEMA IF NOT EXISTS basalt_meta;\n", stdout.String())

	stdout.Reset()
	printInitSQL(c, initFlags{dryRun: true}, "basalt_agent_bot", "", script)
	require.Equal(t, "CREATE SCHEMA IF NOT EXISTS basalt_meta;\n", stdout.String())
}
