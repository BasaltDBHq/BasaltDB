package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// ecmaEscape is a \uXXXX escape of a schema's ECMA pattern, which Go's
// regexp writes as \x{XXXX}.
var ecmaEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

// requireRemoteInitSchema checks stdout against remote-init-result.schema.json.
func requireRemoteInitSchema(t *testing.T, stdout string) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(stdout))
	require.NoError(t, err, stdout)
	require.NoError(t, remoteInitSchema(t).Validate(inst), stdout)
}

func remoteInitSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		return regexp.Compile(regexp.MustCompile(`\{([0-9]+),[0-9]{4,}\}`).ReplaceAllString(ecmaEscape.ReplaceAllString(s, `\x{$1}`), `{$1,}`))
	})
	// $ref values are resolved against each schema's $id (a version URL
	// under /schemas/), so ../links/link.schema.json is loaded as
	// https://basaltvault.app/links/link.schema.json.
	type res struct{ file, url string }
	for _, r := range []res{
		{"../../api/mcp/setup/remote-init-result.schema.json", "https://basaltvault.app/schemas/remote-init-result.v1.json"},
		{"../../api/mcp/errors/next-step.schema.json", "https://basaltvault.app/errors/next-step.schema.json"},
		{"../../api/mcp/links/link.schema.json", "https://basaltvault.app/links/link.schema.json"},
	} {
		raw, err := os.ReadFile(r.file)
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(r.url, doc))
	}
	s, err := c.Compile("https://basaltvault.app/schemas/remote-init-result.v1.json")
	require.NoError(t, err)
	return s
}

func skipIfSystemConfig(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
}

func remoteNoDBOn(t *testing.T, h *fakeHost, jsonOut bool, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(string) string { return "" })
	c.host = h
	c.agentLogin = refusedLogin
	c.probe = noNetworkProbe
	if jsonOut {
		args = append(args, "--json")
	}
	code := runInitAdmin(c, takePathFlags(c, runInit, args))
	return result{code, stdout.String(), stderr.String()}
}

func decodeRemoteResult(t *testing.T, stdout string) RemoteInitResult {
	t.Helper()
	requireRemoteInitSchema(t, stdout)
	var res RemoteInitResult
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&res), stdout)
	return res
}

// Non-root init --remote without --config prints and returns
// `basalt mcp --agent NAME --socket-dir <user config dir>/run` and no
// --config: basalt mcp finds the per-user config, but never the socket
// directory.
func TestInitRemoteMCPCommandDefaultConfig(t *testing.T) {
	t.Parallel()
	skipIfSystemConfig(t)
	h := newFakeHost(t)
	args := []string{
		"--remote", "--agent", "bot", "--write", "public.leads",
		"--database-url", "postgres://postgres@db.example.com:5432/postgres",
	}
	r := remoteNoDBOn(t, h, true, args...)
	require.Equal(t, exitOK, r.code, r.stderr)
	res := decodeRemoteResult(t, r.stdout)
	want := []string{fakeBin, "mcp", "--agent", "bot"}
	require.Equal(t, want, res.MCPCommand)
	txt := remoteNoDBOn(t, h, false, args...)
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "  "+shellJoin(want)+"\n")
	require.NotContains(t, txt.stdout, "--config")
}

// A config in another place gives the same command: basalt mcp finds it.
func TestInitRemoteMCPCommandWithConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "bot", "engine.json")
	args := []string{
		"--remote", "--config", cfg, "--agent", "lead_bot", "--write", "public.leads",
		"--database-url", "postgres://postgres@db.example.com:5432/postgres",
	}
	r := remoteNoDBOn(t, h, true, args...)
	require.Equal(t, exitOK, r.code, r.stderr)
	res := decodeRemoteResult(t, r.stdout)
	want := []string{fakeBin, "mcp", "--agent", "lead_bot"}
	require.Equal(t, want, res.MCPCommand)
	txt := remoteNoDBOn(t, h, false, "--remote", "--config", cfg, "--agent", "lead_bot", "--write", "public.leads")
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "  "+shellJoin(want)+"\n")
}

// Root/service init --remote with a service config returns the command the
// agent's OS user runs for the service socket: only the agent.
func TestInitRemoteMCPCommandAsRootService(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	r := remoteWith(t, func(t *testing.T, a ...string) result {
		t.Helper()
		return cliNoDBEnv(t, noNetworkProbe, map[string]string{envSudoUID: "1234"}, a...)
	}, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	require.True(t, r.cfg.Service())
	require.Equal(t, config.DefaultSocketDir(runtime.GOOS), r.cfg.SocketDir)
	require.Equal(t, []string{fakeBin, "mcp", "--agent", "bot"}, r.res.MCPCommand)
}

// Not root, with a system engine config in place, init --remote stops and
// names it: a second config in the user's folder would make every later
// command stop on two.
func TestInitRemoteRefusesASecondConfigBesideTheSystemOne(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
	require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(string) string { return "" })
	c.host, c.agentLogin, c.probe, c.systemConfigPath = h, refusedLogin, noNetworkProbe, system
	code := runInitAdmin(c, []string{
		"--remote", "--agent", "bot", "--write", "public.leads",
		"--database-url", "postgres://postgres@db.example.com:5432/postgres",
	})
	require.Equal(t, exitError, code, stderr.String())
	require.Contains(t, stderr.String(), system)
	_, err := os.Stat(filepath.Join(h.configDir, perUserDirName, "engine.json"))
	require.ErrorIs(t, err, os.ErrNotExist, "no second config")
}

// init and init --demo, not root, with a system engine config in place and
// --no-service: refused before any SQL, no second config.
func TestInitRefusesAForegroundSetupBesideTheSystemConfig(t *testing.T) {
	t.Parallel()
	for _, extra := range [][]string{
		{"--agent", "bot", "--write", "public.leads"},
		{"--demo"},
	} {
		h := newFakeHost(t)
		system := filepath.Join(h.configDir, "etc", "engine.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
		require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
		var stdout, stderr bytes.Buffer
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
			func(k string) string {
				if k == envAdminURL {
					return "postgres://admin@127.0.0.1:1/postgres"
				}
				return ""
			})
		c.host, c.systemConfigPath = h, system
		code := runInitAdmin(c, append([]string{"--no-service", "--yes", "--skip-passkey"}, extra...))
		require.Equal(t, exitError, code, "%v: %s", extra, stderr.String())
		require.Contains(t, stderr.String(), system)
		_, err := os.Stat(filepath.Join(h.configDir, perUserDirName, "engine.json"))
		require.ErrorIs(t, err, os.ErrNotExist, "no second config")
	}
}

// The backstop for a service declined at the prompt: perUserPaths, which
// moves a foreground setup to the person's folder, refuses beside a system
// config.
func TestPerUserPathsRefusesBesideTheSystemConfig(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	system := filepath.Join(h.configDir, "etc", "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(system), 0o700))
	require.NoError(t, os.WriteFile(system, []byte("{}"), 0o600))
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}},
		func(string) string { return "" })
	c.host, c.systemConfigPath = h, system
	_, err := perUserPaths(c, initFlags{agent: "bot"})
	require.ErrorContains(t, err, system)

	// With no system config it moves to the person's folder.
	require.NoError(t, os.Remove(system))
	f, err := perUserPaths(c, initFlags{agent: "bot"})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(h.configDir, perUserDirName, "engine.json"), f.configPath)
}
