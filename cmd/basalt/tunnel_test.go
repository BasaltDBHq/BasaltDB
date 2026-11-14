package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// tunnelEnv is an engine config with a direct listener and the engine's key
// file next to it.
type tunnelEnv struct {
	config string
	keys   *channel.EngineKeys
}

func newTunnelEnv(t *testing.T, directAddr string) tunnelEnv {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(state, 0o700))
	keys, err := channel.LoadOrCreateKeys(filepath.Join(state, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	path := filepath.Join(dir, "engine.json")
	require.NoError(t, config.UpsertAgent(path, config.Settings{
		SocketDir: "/run/b", StateDir: state, PagesURL: links.Portal, OperatedBy: "AGENT", DirectAddr: directAddr,
	}, config.Agent{Name: "bot", OSUser: "bot", CredentialFile: filepath.Join(dir, "bot.url")}))
	return tunnelEnv{config: path, keys: keys}
}

// run is basalt tunnel with probe standing for the network.
func (e tunnelEnv) run(t *testing.T, probe func(string) (probeAnswer, error), args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
	c.host = systemSocketHost(t)
	c.probe = func(_ context.Context, url string) (probeAnswer, error) { return probe(url) }
	code := runTunnel(c, append([]string{"--config", e.config}, args...))
	return result{code, stdout.String(), stderr.String()}
}

func (e tunnelEnv) answer(t *testing.T) probeAnswer {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"engineKey": base64.RawURLEncoding.EncodeToString(e.keys.PublicKeySPKI()), "engineId": e.keys.EngineID(),
	})
	require.NoError(t, err)
	return probeAnswer{status: http.StatusOK, json: true, body: body}
}

func noNetwork(string) (probeAnswer, error) {
	return probeAnswer{}, errors.New("no network in this test")
}

// Without an address it prints the three ways to publish, forwarding to
// the config's directAddr, and checks nothing.
func TestTunnelPrintsTheCommands(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	r := e.run(t, noNetwork)
	require.Equal(t, exitOK, r.code, r.stderr)
	for _, want := range []string{
		"127.0.0.1:9100",
		"cloudflared tunnel run --url http://127.0.0.1:9100 basalt-engine",
		"cloudflared tunnel route dns basalt-engine engine.example.com",
		"tailscale funnel --bg http://127.0.0.1:9100",
		"cloudflared tunnel login",
		"engine.example.com {\n      reverse_proxy 127.0.0.1:9100\n  }",
		"pass the public Host unchanged",
	} {
		require.Contains(t, r.stdout, want)
	}
	require.Empty(t, r.stderr)
}

func TestTunnelNamesYourAddressInTheCommands(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	r := e.run(t, func(string) (probeAnswer, error) { return e.answer(t), nil }, "--address", "https://basalt.mine.dev")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "cloudflared tunnel route dns basalt-engine basalt.mine.dev")
	require.Contains(t, r.stdout, "basalt.mine.dev {\n      reverse_proxy 127.0.0.1:9100")
	require.NotContains(t, r.stdout, "engine.example.com")
}

// directAddr off, or no config, still prints the commands for the address
// basalt init --direct-addr documents, and says what the engine needs.
func TestTunnelWithoutAListener(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "off")
	r := e.run(t, noNetwork)
	require.Equal(t, exitOK, r.code)
	require.Contains(t, r.stdout, "127.0.0.1:8787")
	require.Contains(t, r.stderr, "directAddr is off")
	require.Contains(t, r.stderr, "--direct-addr 127.0.0.1:8787")

	r = e.run(t, noNetwork, "--config", filepath.Join(t.TempDir(), "missing.json"))
	require.Equal(t, exitOK, r.code)
	require.Contains(t, r.stdout, "127.0.0.1:8787")
	require.Contains(t, r.stderr, "engine.json not read here")

	r = e.run(t, noNetwork, "--direct-addr", "127.0.0.1:9300")
	require.Equal(t, exitOK, r.code)
	require.Contains(t, r.stdout, "reverse_proxy 127.0.0.1:9300")
}

func TestTunnelUsageErrors(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	for _, args := range [][]string{
		{"--address", "http://engine.example.com"},
		{"--address", "https://engine.example.com/path"},
		{"--address", "https://localhost"},
		{"--address", "https://engine.example.com:443"},
		{"--direct-addr", "0.0.0.0:8787"},
		{"--direct-addr", "off"},
		{"stray"},
	} {
		r := e.run(t, noNetwork, args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, r.stdout, "%v", args)
	}
}

func TestTunnelChecksTheAddress(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	var asked string
	r := e.run(t, func(url string) (probeAnswer, error) { asked = url; return e.answer(t), nil }, "--address", "https://engine.example.com")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, "https://engine.example.com/v1/engine", asked)
	require.Contains(t, r.stdout, "answers and serves this engine's key")
	require.Contains(t, r.stdout, channel.FingerprintOf(e.keys.EngineID()))
	require.Contains(t, r.stdout, "basalt init --setup-code <the agent's code> --engine-url https://engine.example.com")
	require.Contains(t, r.stdout, "https://portal.basaltvault.app/engines/add")
}

func TestTunnelRefusesWhatItCannotTrust(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	other, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	otherBody, err := json.Marshal(map[string]string{
		"engineKey": base64.RawURLEncoding.EncodeToString(other.PublicKeySPKI()), "engineId": other.EngineID(),
	})
	require.NoError(t, err)
	forgedBody, err := json.Marshal(map[string]string{
		"engineKey": base64.RawURLEncoding.EncodeToString(e.keys.PublicKeySPKI()), "engineId": other.EngineID(),
	})
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		answer probeAnswer
		err    error
		want   string
	}{
		"unreachable":           {err: errors.New("dial tcp: no such host"), want: "does not answer"},
		"another engine's key":  {answer: probeAnswer{status: 200, json: true, body: otherBody}, want: "another engine's key"},
		"id is not the hash":    {answer: probeAnswer{status: 200, json: true, body: forgedBody}, want: "not the hash of its key"},
		"host not recorded":     {answer: probeAnswer{status: 400, body: []byte("host not allowed\n")}, want: "record the address first"},
		"Host rewritten":        {answer: probeAnswer{status: 400, body: []byte("host not allowed\n")}, want: "does not pass the public Host on unchanged"},
		"local pages listener":  {answer: probeAnswer{status: 400, body: []byte("host not allowed: engine.example.com\n")}, want: "not the engine's direct listener"},
		"tunnel not connected":  {answer: probeAnswer{status: 530}, want: "not connected"},
		"tunnel cannot connect": {answer: probeAnswer{status: 502}, want: "not connected to the engine's direct listener"},
		"wrong service":         {answer: probeAnswer{status: 404}, want: "not the engine's direct listener"},
		"not JSON":              {answer: probeAnswer{status: 200, body: []byte("<html>")}, want: "not JSON"},
		"JSON of another shape": {answer: probeAnswer{status: 200, json: true, body: []byte("[1]")}, want: "cannot read"},
	} {
		r := e.run(t, func(string) (probeAnswer, error) { return tc.answer, tc.err }, "--address", "https://engine.example.com")
		require.Equal(t, exitError, r.code, name+": "+r.stderr)
		require.Contains(t, r.stderr, tc.want, name)
		require.NotContains(t, r.stdout, "answers and serves", name)
	}
}

// Without this machine's key file the check still proves the id is the
// key's hash, and says to compare the fingerprint by hand.
func TestTunnelWithoutTheLocalKey(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "127.0.0.1:9100")
	other, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]string{
		"engineKey": base64.RawURLEncoding.EncodeToString(other.PublicKeySPKI()), "engineId": other.EngineID(),
	})
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(e.config), "state", channel.KeyFileName)))
	r := e.run(t, func(string) (probeAnswer, error) { return probeAnswer{status: 200, json: true, body: body}, nil }, "--address", "https://engine.example.com")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "this machine's key file was not read")
	require.Contains(t, r.stdout, channel.FingerprintOf(other.EngineID()))
}

func TestTunnelStripsThePortFromTheDNSName(t *testing.T) {
	t.Parallel()
	e := newTunnelEnv(t, "[::1]:9100")
	r := e.run(t, func(string) (probeAnswer, error) { return e.answer(t), nil }, "--address", "https://engine.example.com:8443")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "route dns basalt-engine engine.example.com\n")
	require.Contains(t, r.stdout, "tailscale funnel --bg http://[::1]:9100")
	require.Contains(t, r.stdout, "  engine.example.com:8443 {\n      reverse_proxy [::1]:9100", "Caddy keeps the port")
}
