package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestForegroundNext(t *testing.T) {
	t.Parallel()
	f := initFlags{
		agent: "bot", configPath: "/home/iman/basalt/engine.json", socketDir: "/home/iman/basalt/run", osUser: "iman",
	}
	require.Equal(t, `next, start the engine; it runs in the foreground as you (same-user mode: writes are guarded, but your OS user can read the credential):
  basalt engine --config /home/iman/basalt/engine.json
then add this MCP server to the agent's client, running as OS user iman (docs/mcp-clients.md):
  basalt mcp --agent bot --socket-dir /home/iman/basalt/run
`, foregroundNext(f, "linux"))

	f.configPath, f.socketDir = "/Users/me/Library/Application Support/basalt/engine.json", config.DefaultSocketDir("darwin")
	require.Contains(t, foregroundNext(f, "darwin"), "basalt engine --config '/Users/me/Library/Application Support/basalt/engine.json'")
	require.True(t, strings.HasSuffix(foregroundNext(f, "darwin"), "  basalt mcp --agent bot\n"), "the default socket dir needs no flag")
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
	require.Equal(t, config.Settings{SocketDir: "/run/basalt"}, engineSettings(f, "linux"))

	// A per-user config keeps its state next to it; a development passkey
	// origin serves the approval page.
	f = initFlags{
		configPath: "/home/iman/basalt/engine.json", socketDir: "/home/iman/basalt/run",
		passkeyOrigin: "http://localhost:8787",
	}
	require.Equal(t, config.Settings{
		SocketDir: "/home/iman/basalt/run", StateDir: "/home/iman/basalt/state",
		PagesURL: "http://localhost:8787",
	}, engineSettings(f, "linux"))
}

func TestServiceInstallArgsKeepTheCredentialFileWhenThePasswordIsKept(t *testing.T) {
	t.Parallel()
	f := initFlags{agent: "bot", configPath: "/etc/basalt/engine.json", engineUser: "basalt", osUser: "iman",
		keepCredential: true, initArgs: []string{"--agent=bot", "--os-user=iman"}}
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
