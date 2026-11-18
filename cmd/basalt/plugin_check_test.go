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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// testPluginFlag makes the test binary the test plugin: a JSON-RPC plugin
// on stdin and stdout that answers initialize from its own installed
// manifest, health with the status its argument names, and shutdown.
const testPluginFlag = "--basalt-test-plugin"

// testPluginMain never returns.
func testPluginMain(args []string) {
	status := protocol.HealthReady
	if len(args) > 0 && args[0] == "not-ready" {
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
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			os.Exit(0)
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
		_, _ = os.Stdout.Write(append(b, '\n'))
		if req.Method == protocol.MethodShutdown {
			os.Exit(0)
		}
	}
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

	e.person("add", e.checkSource("jsonrpc-stdio", "not-ready"), "--agents", "product_a", "--instance", "sick")
	e.setTimeout("sick")
	r := e.run(nil, "", "check", "acme-ner", "--instance", "sick")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "health NOT_READY")
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

func TestCheckRefusesTransportsNotServed(t *testing.T) {
	t.Parallel()
	e := newPluginEngine(t)
	e.person("add", e.checkSource("jsonrpc-unix"), "--agents", "product_a")
	e.person("add", e.checkSource("connectrpc"), "--agents", "product_a", "--instance", "grpc")
	r := e.run(nil, "", "check", "acme-ner")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "jsonrpc-unix plugin is not served by this build yet")
	r = e.run(nil, "", "check", "acme-ner", "--instance", "grpc")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "connectrpc plugin is not served by this build yet")
	r = e.run(nil, "y\n", "enable", "acme-ner", "--instance", "grpc")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "a local plugin over connectrpc is not served yet")
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
