//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// liveEngine is a same-user engine running in this process, as a person
// runs it in the foreground, with agent product_a on a real guard, a
// person's passkey on its database, and the SDK's template plugin ready to
// add, unsigned. The engine is started once and never restarted.
type liveEngine struct {
	t          *testing.T
	d          *guardtest.DB
	role       string
	configPath string
	socketDir  string
	stateDir   string
	pk         *passkeytest.Authenticator
	// src is the template plugin's directory, with no .sig.
	src string
}

func newLiveEngine(t *testing.T) *liveEngine {
	t.Helper()
	bin := buildTemplate(t)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "product_a", []string{"public.leads"}, nil)
	dir, err := os.MkdirTemp("", "blive") // short: macOS bounds socket paths
	require.NoError(t, err)
	dir, err = filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	e := &liveEngine{
		t: t, d: d, role: a.Role, configPath: filepath.Join(dir, "config", "engine.json"),
		socketDir: filepath.Join(dir, "run"), stateDir: filepath.Join(dir, "state"), src: filepath.Join(dir, "src"),
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(e.configPath), 0o700))
	cred := filepath.Join(dir, "config", "product_a.url")
	require.NoError(t, os.WriteFile(cred, []byte(a.URL+"\n"), config.FileMode))
	me, err := user.Current()
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{
		"socketDir": e.socketDir, "stateDir": e.stateDir, "pagesAddr": "off", "mode": "SAME_USER",
		"agents": []map[string]any{{"name": "product_a", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(e.configPath, raw))

	require.NoError(t, os.MkdirAll(filepath.Join(e.src, "bin"), 0o755))
	sum := copyExecutable(t, bin, filepath.Join(e.src, "bin", "hello-feed"))
	require.NoError(t, os.WriteFile(filepath.Join(e.src, plugin.ManifestFile), []byte(fmt.Sprintf(templateManifest, "jsonrpc-stdio", `[]`, sum)), 0o644))

	e.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, e.pk.Credential(), "app"))
	return e
}

// start runs the engine until the test ends.
func (e *liveEngine) start() {
	e.t.Helper()
	cfg, err := config.Load(e.configPath)
	require.NoError(e.t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx, cfg, e.configPath, slog.New(slog.DiscardHandler)) }()
	e.t.Cleanup(func() {
		cancel()
		require.NoError(e.t, <-done)
	})
	require.Eventually(e.t, func() bool {
		c, err := net.Dial("unix", config.SocketPath(e.socketDir, "product_a"))
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 30*time.Second, 20*time.Millisecond)
}

// agent runs basalt plugin args as product_a's agent: the agent marker set,
// no terminal, nothing typed.
func (e *liveEngine) agent(args ...string) result {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return agentEnv[k] })
	code := runPlugin(c, append(args, "--config", e.configPath))
	return result{code, stdout.String(), stderr.String()}
}

// sign is what the person's passkey does on the page the link opens: the
// code the page shows, which the person pastes into the chat.
func (e *liveEngine) sign(url string) string {
	e.t.Helper()
	req, _ := requestOf(e.t, url)
	as, err := e.pk.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(e.t, err)
	code, err := approval.NewPluginApprovalResponse(req.ApprovalID, as).Code()
	require.NoError(e.t, err)
	return code
}

// pluginProblems are the PLUGIN_ problems the agent's status tool shows, as
// its MCP client reads them from the engine's socket.
func (e *liveEngine) pluginProblems() []string {
	e.t.Helper()
	conn, err := net.Dial("unix", config.SocketPath(e.socketDir, "product_a"))
	require.NoError(e.t, err)
	defer conn.Close()
	require.NoError(e.t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	require.NoError(e.t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(e.t, err)
	line, err := r.ReadString('\n')
	require.NoError(e.t, err)
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(e.t, resp.Result.Content, 1, line)
	var report struct {
		Problems []struct {
			Code string `json:"code"`
		} `json:"problems"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &report), line)
	var out []string
	for _, p := range report.Problems {
		if strings.HasPrefix(p.Code, "PLUGIN_") {
			out = append(out, p.Code)
		}
	}
	return out
}

// TestAgentAddStartsWithoutRestart is the seamless path end to end: the
// engine runs with no plugin; the agent runs basalt plugin add, hands the
// link over and, when the person pastes the code the page gave their
// passkey, runs basalt plugin approve. Within a few seconds the agent's
// status shows the plugin serving, with no engine restart and nothing a
// person typed but the passkey's code.
func TestAgentAddStartsWithoutRestart(t *testing.T) {
	t.Parallel()
	e := newLiveEngine(t)
	e.start()
	require.Empty(t, e.pluginProblems())

	r := e.agent("add", e.src, "--agents", "product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stdout+r.stderr, "restart")
	var res approvalResult
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &res))
	require.Len(t, res.Approvals, 1)
	require.Eventually(t, func() bool {
		p := e.pluginProblems()
		return len(p) == 1 && p[0] == "PLUGIN_AWAITING_APPROVAL"
	}, 15*time.Second, 100*time.Millisecond, "the running engine sees the entry and waits for its approval")

	r = e.agent("approve", e.sign(res.Approvals[0].URL))
	require.Equal(t, exitOK, r.code, r.stderr)
	signed := time.Now()
	require.Eventually(t, func() bool { return len(e.pluginProblems()) == 0 }, 15*time.Second, 100*time.Millisecond,
		"the plugin serves the agent without a restart")
	require.Less(t, time.Since(signed), 10*time.Second)
}
