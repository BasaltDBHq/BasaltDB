//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// testPluginFlag makes the test binary the test plugin: a JSON-RPC plugin
// on stdin and stdout that answers initialize from its own installed
// manifest, health with the status its argument names, and shutdown.
const testPluginFlag = "--basalt-test-plugin"

// testPluginMain never returns. Its arguments: "not-ready" answers health
// NOT_READY; "connect" serves ConnectRPC instead of JSON-RPC. With the
// socket variable set it listens there, else it speaks on stdin and stdout.
func testPluginMain(args []string) {
	status := protocol.HealthReady
	if slices.Contains(args, "not-ready") {
		status = protocol.HealthNotReady
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "..", plugin.ManifestFile))
	if err != nil {
		os.Exit(1)
	}
	m, err := plugin.ParseManifest(raw)
	if err != nil {
		os.Exit(1)
	}
	sock := os.Getenv(dial.SocketEnv)
	// It answers nothing unless it got exactly the environment a plugin
	// gets (the socket variable alone, or nothing for stdio) and runs in its
	// installed copy.
	wantEnv := []string{}
	if sock != "" {
		wantEnv = []string{dial.SocketEnv + "=" + sock}
	}
	cwd, err := os.Getwd()
	if err == nil {
		cwd, err = filepath.EvalSymlinks(cwd)
	}
	copyDir, dirErr := filepath.EvalSymlinks(filepath.Join(filepath.Dir(exe), ".."))
	if !slices.Equal(os.Environ(), wantEnv) || err != nil || dirErr != nil || cwd != copyDir {
		os.Exit(3)
	}
	if sock == "" {
		serveJSONRPC(os.Stdin, os.Stdout, m, status)
		os.Exit(0)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(1)
	}
	if slices.Contains(args, "connect") {
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		path, h := pluginv1connect.NewPluginServiceHandler(testConnectPlugin{m: m, status: status})
		mux := http.NewServeMux()
		mux.Handle(path, h)
		_ = (&http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Minute}).Serve(l)
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(1)
		}
		go serveJSONRPC(c, c, m, status)
	}
}

// serveJSONRPC answers initialize, health and shutdown, one line each.
func serveJSONRPC(r io.Reader, w io.Writer, m plugin.Manifest, status string) {
	in := bufio.NewReader(r)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(line, &req) != nil {
			os.Exit(1)
		}
		var result any
		switch req.Method {
		case protocol.MethodInitialize:
			result = protocol.InitializeResponse{Protocol: protocol.Version1, Name: m.Name, Version: m.Version, Hooks: m.Hooks}
		case protocol.MethodHealth:
			result = protocol.HealthResponse{Status: status}
		default:
			result = struct{}{}
		}
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if err != nil {
			os.Exit(1)
		}
		_, _ = w.Write(append(b, '\n'))
		if req.Method == protocol.MethodShutdown {
			os.Exit(0)
		}
	}
}

// testConnectPlugin is the test plugin over ConnectRPC.
type testConnectPlugin struct {
	pluginv1connect.UnimplementedPluginServiceHandler
	m      plugin.Manifest
	status string
}

func (p testConnectPlugin) Initialize(context.Context, *connectrpc.Request[pluginv1.InitializeRequest]) (*connectrpc.Response[pluginv1.InitializeResponse], error) {
	hooks := map[string]*pluginv1.HookDeclaration{}
	for name, d := range p.m.Hooks {
		hooks[name] = &pluginv1.HookDeclaration{Contract: d.Contract, Roles: d.Roles, EntityTypes: d.EntityTypes}
	}
	return connectrpc.NewResponse(&pluginv1.InitializeResponse{Protocol: protocol.Version1, Name: p.m.Name, Version: p.m.Version, Hooks: hooks}), nil
}

func (p testConnectPlugin) Health(context.Context, *connectrpc.Request[pluginv1.HealthRequest]) (*connectrpc.Response[pluginv1.HealthResponse], error) {
	return connectrpc.NewResponse(&pluginv1.HealthResponse{Status: p.status}), nil
}

func (testConnectPlugin) Shutdown(context.Context, *connectrpc.Request[pluginv1.ShutdownRequest]) (*connectrpc.Response[pluginv1.ShutdownResponse], error) {
	go func() { time.Sleep(50 * time.Millisecond); os.Exit(0) }()
	return connectrpc.NewResponse(&pluginv1.ShutdownResponse{}), nil
}

// checkSource writes a signed local plugin whose command is this test
// binary, started with args, using transport.
func (e *pluginEngine) checkSource(transport string, args ...string) string {
	e.t.Helper()
	dir, err := os.MkdirTemp(e.base, "src-")
	require.NoError(e.t, err)
	require.NoError(e.t, os.Mkdir(filepath.Join(dir, "bin"), 0o755))
	exe, err := os.Executable()
	require.NoError(e.t, err)
	src, err := os.Open(exe)
	require.NoError(e.t, err)
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, "bin", "acme-ner"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	require.NoError(e.t, err)
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(dst, h), src)
	require.NoError(e.t, err)
	require.NoError(e.t, dst.Close())
	argsJSON, err := json.Marshal(append([]string{testPluginFlag}, args...))
	require.NoError(e.t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": "1.4.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "local": { "transport": %q, "command": "bin/acme-ner", "args": %s } },
  "files": { "bin/acme-ner": "sha256:%x" },
  "network": { "egress": [] }
}
`, transport, argsJSON, h.Sum(nil))
	require.NoError(e.t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))
	sig, err := plugin.SignManifest([]byte(manifest), e.signer)
	require.NoError(e.t, err)
	require.NoError(e.t, os.WriteFile(filepath.Join(dir, plugin.SignatureFile), sig, 0o644))
	return dir
}

// setTimeout gives an entry a call deadline a cold start of the test
// binary under -race fits in.
func (e *pluginEngine) setTimeout(instance string) {
	e.t.Helper()
	require.NoError(e.t, config.UpdateConfig(e.configPath, config.Change{Apply: func(c *config.Config) error {
		c.Plugins[c.PluginIndex(plugin.EntryKey{Name: "acme-ner", Instance: instance})].TimeoutMs = config.MaxPluginTimeoutMs
		return nil
	}}))
}

func TestCheckRunsInitializeAndHealth(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.person("add", e.checkSource("jsonrpc-stdio"), "--agents", "product_a")
	e.setTimeout("default")
	before := e.snapshot()

	// check changes nothing, so an agent may run it too.
	for _, env := range []map[string]string{nil, {"CLAUDECODE": "1"}} {
		r := e.run(env, "", "check", "acme-ner")
		require.Equal(t, exitOK, r.code, r.stderr)
		require.Regexp(t, `^plugin acme-ner/default: initialize [0-9.]+[µm]?s, health READY [0-9.]+[µm]?s\n$`, r.stdout)
	}
	require.Equal(t, before, e.snapshot(), "check writes nothing")

	// --json prints the result as one JSON document and no text line.
	res := checkResultOf(t, e.run(nil, "", "check", "acme-ner", "--json"))
	require.Equal(t, "acme-ner", res.Name)
	require.Equal(t, "default", res.Instance)
	require.Equal(t, "READY", res.Health.Status)
	require.Empty(t, res.Hooks, "wire.detect has no sample yet")

	e.person("add", e.checkSource("jsonrpc-stdio", "not-ready"), "--agents", "product_a", "--instance", "sick")
	e.setTimeout("sick")
	r := e.run(nil, "", "check", "acme-ner", "--instance", "sick")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "health NOT_READY")
	require.Contains(t, r.stderr, "answered health NOT_READY")
	// A failed check prints no result: with --json stdout stays empty.
	r = e.run(nil, "", "check", "acme-ner", "--instance", "sick", "--json")
	require.Equal(t, exitError, r.code)
	require.Empty(t, r.stdout)
	require.Contains(t, r.stderr, "answered health NOT_READY")

	// A changed installed file is refused before anything starts.
	p := e.config().Plugins[0]
	bin := filepath.Join(e.root, "acme-ner", "default", p.ManifestSHA256, "bin", "acme-ner")
	require.NoError(t, os.Chmod(bin, 0o755))
	f, err := os.OpenFile(bin, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	_, err = f.WriteString("x")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	refusal(t, e.run(nil, "", "check", "acme-ner", "--json"), "NOT_TRUSTED")
}

// checkResultOf decodes a successful check --json and checks it against
// api/plugin/check.schema.json.
func checkResultOf(t *testing.T, r result) checkResult {
	t.Helper()
	require.Equal(t, exitOK, r.code, r.stderr)
	raw, err := os.ReadFile("../../api/plugin/check.schema.json")
	require.NoError(t, err)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	const id = "https://basaltvault.app/schemas/plugin/check.v1.json"
	require.NoError(t, c.AddResource(id, doc))
	s, err := c.Compile(id)
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(r.stdout))
	require.NoError(t, err, r.stdout+r.stderr)
	require.NoError(t, s.Validate(inst), r.stdout)
	var res checkResult
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &res))
	return res
}

// TestCheckRefusesALocalPluginAsRoot: check never starts a local plugin
// with root's privileges, as the engine never does.
func TestCheckRefusesALocalPluginAsRoot(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.person("add", e.checkSource("jsonrpc-stdio"), "--agents", "product_a")
	e.host.euid = 0
	r := e.run(nil, "", "check", "acme-ner")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "never started with root's privileges")
	require.Empty(t, r.stdout, "nothing was started")
}

// TestCheckServesEveryLocalTransport: a socket plugin is started with the
// socket path in its environment and reached over it.
func TestCheckServesEveryLocalTransport(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	for inst, src := range map[string]string{
		"unix":    e.checkSource("jsonrpc-unix"),
		"grpc":    e.checkSource("connectrpc", "connect"),
		"sickrpc": e.checkSource("connectrpc", "connect", "not-ready"),
	} {
		e.person("add", src, "--agents", "product_a", "--instance", inst)
		e.setTimeout(inst)
	}
	for _, inst := range []string{"unix", "grpc"} {
		r := e.run(nil, "", "check", "acme-ner", "--instance", inst)
		require.Equal(t, exitOK, r.code, "%s: %s", inst, r.stderr)
		require.Contains(t, r.stdout, "health READY", inst)
	}
	r := e.run(nil, "", "check", "acme-ner", "--instance", "sickrpc")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "health NOT_READY")
	r = e.person("enable", "acme-ner", "--instance", "grpc")
	require.Contains(t, r.stderr, "enabled", "a local connectrpc plugin can be enabled")
}

// runAuthor runs an author command, which takes no --config.
func (e *pluginEngine) runAuthor(env map[string]string, args ...string) result {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return env[k] })
	c.host = e.host
	code := runPlugin(c, args)
	r := result{code, stdout.String(), stderr.String()}
	require.NotContains(e.t, r.stdout+r.stderr, "PRIVATE KEY", "no key material in any output")
	require.NotContains(e.t, r.stdout+r.stderr, "BEGIN")
	return r
}

// The author commands never read the engine config, so --config is a usage
// error for both.
func TestAuthorCommandsTakeNoConfig(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	cfg := filepath.Join(e.base, "engine.json")
	for _, args := range [][]string{
		{"keygen", "--out", filepath.Join(e.base, "k"), "--config", cfg},
		{"sign", e.base, "--key", filepath.Join(e.base, "k.key"), "--config", cfg},
	} {
		r := e.runAuthor(nil, args...)
		require.Equal(t, exitUsage, r.code, r.stderr)
		require.Contains(t, r.stderr, "config")
	}
}

// TestKeygenAndSign: keygen and sign are author commands, allowed under an
// agent marker. A directory signed with sign passes verification once its
// public key is trusted, and fails after a 1-byte change.
func TestKeygenAndSign(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	agent := map[string]string{"CLAUDECODE": "1"}
	keys := filepath.Join(e.base, "keys")
	r := e.runAuthor(agent, "keygen", "--out", keys)
	require.Equal(t, exitOK, r.code, r.stderr)
	var id, pub string
	_, err := fmt.Sscanf(r.stdout, "key id %s\npublic key %s\n", &id, &pub)
	require.NoError(t, err, r.stdout)
	require.Equal(t, filepath.Join(keys, id+".pub"), pub)
	priv := filepath.Join(keys, id+".key")
	fi, err := os.Stat(priv)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	privBytes, err := os.ReadFile(priv)
	require.NoError(t, err)
	require.NotContains(t, r.stdout+r.stderr, strings.TrimSpace(string(privBytes)))

	src := filepath.Join(e.base, "src-authored")
	e.writePlugin(src, pluginManifest("1.0.0", `"feed.observe": {"contract": "feed/1"}`, ""), e.signer)
	r = e.runAuthor(agent, "sign", src, "--key", priv)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, fmt.Sprintf("signed by key %s\nsignature %s\n", id, filepath.Join(src, plugin.SignatureFile)), r.stdout)

	refusal(t, e.run(nil, "y\n", "add", src, "--agents", "product_a", "--json"), "NOT_TRUSTED")
	e.person("trust", pub)
	e.person("add", src, "--agents", "product_a")
	p := e.config().Plugins[0]
	v, err := plugin.Verify(e.root, p.Key(), p.ManifestSHA256, e.trustStore(), plugin.ModeSameUser)
	require.NoError(t, err)
	require.Equal(t, id, v.SignerKeyID)

	// One byte changed after signing fails.
	mp := filepath.Join(src, plugin.ManifestFile)
	b, err := os.ReadFile(mp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mp, bytes.Replace(b, []byte("1.0.0"), []byte("1.0.1"), 1), 0o644))
	refusal(t, e.run(nil, "y\n", "add", src, "--agents", "product_a", "--json"), "NOT_TRUSTED")

	// A key readable by others is refused; the error names the file only.
	require.NoError(t, os.Chmod(priv, 0o644))
	r = e.runAuthor(nil, "sign", src, "--key", priv)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "key file "+priv+" is mode 0644")
	require.NoError(t, os.Chmod(priv, 0o600))

	// A bad manifest is refused with the rule, and no signature is written.
	require.NoError(t, os.WriteFile(mp, []byte(pluginManifest("1.0.0", `"wire.verdict": {"contract": "verdict/1"}`, "")), 0o644))
	sigBefore, err := os.ReadFile(filepath.Join(src, plugin.SignatureFile))
	require.NoError(t, err)
	r = e.runAuthor(nil, "sign", src, "--key", priv)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "BAD_MANIFEST")
	sigAfter, err := os.ReadFile(filepath.Join(src, plugin.SignatureFile))
	require.NoError(t, err)
	require.Equal(t, sigBefore, sigAfter)

	require.Equal(t, exitUsage, e.runAuthor(nil, "keygen").code)
	require.Equal(t, exitUsage, e.runAuthor(nil, "sign", src).code)
}
