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
	code := runInit(c, args)
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
	socketDir := filepath.Join(h.configDir, perUserDirName, "run")
	want := []string{"basalt", "mcp", "--agent", "bot", "--socket-dir", socketDir}
	require.Equal(t, want, res.MCPCommand)
	txt := remoteNoDBOn(t, h, false, args...)
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "  "+shellJoin(want)+"\n")
	require.NotContains(t, txt.stdout, "--config")
}

// Non-root init --remote --config prints and returns the command with
// --config and the matching --socket-dir next to it.
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
	abs, err := filepath.Abs(cfg)
	require.NoError(t, err)
	want := []string{"basalt", "mcp", "--agent", "lead_bot", "--socket-dir", filepath.Join(filepath.Dir(abs), "run"), "--config", abs}
	require.Equal(t, want, res.MCPCommand)
	txt := remoteNoDBOn(t, h, false, "--remote", "--config", cfg, "--agent", "lead_bot", "--write", "public.leads")
	require.Equal(t, exitOK, txt.code, txt.stderr)
	require.Contains(t, txt.stdout, "  "+shellJoin(want)+"\n")
}

// Root/service init --remote with a service config returns the command the
// agent's OS user runs for the service socket: no --socket-dir, because
// the sockets stay at the system default, and --config when the file is
// not the system default.
func TestInitRemoteMCPCommandAsRootService(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	r := remoteWith(t, func(t *testing.T, a ...string) result {
		t.Helper()
		return cliNoDBEnv(t, noNetworkProbe, map[string]string{envSudoUID: "1234"}, a...)
	}, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	require.True(t, r.cfg.Service())
	require.Equal(t, config.DefaultSocketDir(runtime.GOOS), r.cfg.SocketDir)
	abs, err := filepath.Abs(cfg)
	require.NoError(t, err)
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot", "--config", abs}, r.res.MCPCommand)
	require.NotContains(t, r.res.MCPCommand, "--socket-dir")
}
