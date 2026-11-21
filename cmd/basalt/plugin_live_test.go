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

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
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
	code := runPlugin(c, takePathFlags(c, runPlugin, append(args, "--config", e.configPath)))
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

// waitResultOf decodes and checks a wait's result against
// api/plugin/approval/wait.schema.json.
func waitResultOf(t *testing.T, r result) waitResult {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for _, f := range []string{"../../api/plugin/approval/wait.schema.json", "../../api/mcp/errors/next-step.schema.json"} {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		var head struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(raw, &head))
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(head.ID, doc))
	}
	s, err := c.Compile("https://basaltvault.app/schemas/plugin/approval/wait.v1.json")
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(r.stdout))
	require.NoError(t, err, r.stdout+r.stderr)
	require.NoError(t, s.Validate(inst), r.stdout)
	var res waitResult
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &res))
	return res
}

// command runs a step's command line, "basalt plugin ...", as the agent.
func (e *liveEngine) command(line string) result {
	e.t.Helper()
	rest, ok := strings.CutPrefix(line, "basalt plugin ")
	require.True(e.t, ok, "a basalt plugin command: %q", line)
	return e.agent(strings.Fields(rest)...)
}

// The wait: the agent's add hands the link over at once, with a step that
// waits in the same turn. Run while the person has not signed, it ends after
// its --wait as WAITING and tells the agent to end its turn; run again, it
// returns RUNNING as soon as the person's signature reaches the engine and
// the plugin answers READY, so the agent says "done" in that turn. A wait
// on an approval a newer one replaced ends at once.
func TestAddWaitReturnsWhenRunning(t *testing.T) {
	t.Parallel()
	e := newLiveEngine(t)
	e.start()

	start := time.Now()
	r := e.agent("add", e.src, "--agents", "product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Less(t, time.Since(start), 30*time.Second, "the link at once, no wait by default")
	res := approvalResultOf(t, r)
	require.Equal(t, []string{"PERSON OPEN_LINK", "AGENT RUN_COMMAND", "PERSON TELL_AGENT", "AGENT END_TURN"}, stepKinds(res.NextSteps))
	wait := res.NextSteps[1].Command
	require.Contains(t, wait, "basalt plugin enable hello-feed --approval-id "+res.Approvals[0].ApprovalID+" --json")

	// Not signed: the wait ends, nothing opened or written.
	before, err := os.ReadFile(e.configPath)
	require.NoError(t, err)
	r = e.command(wait + " --wait 2")
	require.Equal(t, exitOK, r.code, r.stderr)
	w := waitResultOf(t, r)
	require.Equal(t, waitWaiting, w.State)
	require.Equal(t, statePending, w.Approvals[0].State)
	require.Equal(t, []string{"product_a"}, w.Approvals[0].Agents)
	require.Equal(t, []string{"PERSON TELL_AGENT", "AGENT END_TURN"}, stepKinds(w.NextSteps))
	after, err := os.ReadFile(e.configPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "a wait writes nothing")

	// The person signs while the agent waits.
	done := make(chan result, 1)
	go func() { done <- e.command(wait) }()
	time.Sleep(time.Second)
	signed := e.agent("approve", e.sign(res.Approvals[0].URL))
	require.Equal(t, exitOK, signed.code, signed.stderr)
	at := time.Now()
	r = <-done
	require.Equal(t, exitOK, r.code, r.stderr)
	w = waitResultOf(t, r)
	require.Equal(t, waitRunning, w.State, r.stdout)
	require.Less(t, time.Since(at), 15*time.Second)
	require.Equal(t, []string{"AGENT STOP"}, stepKinds(w.NextSteps))
	require.Equal(t, "The plugin hello-feed runs now for product_a.", w.PersonMessage)
	require.Empty(t, e.pluginProblems(), "it runs as the wait said")

	// Called again once it runs: at once.
	start = time.Now()
	r = e.command(wait)
	require.Equal(t, waitRunning, waitResultOf(t, r).State)
	require.Less(t, time.Since(start), 5*time.Second)

	// A newer approval replaces it: the wait on the old one ends at once.
	r = e.agent("enable", "hello-feed", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	start = time.Now()
	r = e.command(wait)
	require.Equal(t, exitError, r.code)
	w = waitResultOf(t, r)
	require.Equal(t, waitEnded, w.State)
	require.Equal(t, stateCancelled, w.Approvals[0].State)
	require.Less(t, time.Since(start), 5*time.Second)
}

// A database that does not answer decides nothing: an approval no agent
// could read is neither signed nor ended, so the wait goes on; once every
// agent answered, one that none shows has ended.
func TestWaitUndecidedWhileDatabaseDown(t *testing.T) {
	t.Parallel()
	e := &pluginEnv{c: newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })}
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	id := uuid.New()
	listed := []string{"product_a", "product_b"}

	w, signed, open := e.waitStates([]uuid.UUID{id}, listed, map[string]waitAgentRead{})
	require.False(t, signed)
	require.True(t, open, "nobody answered: nothing ended")
	require.Equal(t, stateNone, w[0].State)

	approved := guard.PluginApprovalRecord{ApprovalID: id, Name: k.Name, Instance: k.Instance, Status: guard.PluginApprovalStatusApproved, NamesCaller: true}
	one := map[string]waitAgentRead{"product_a": {newest: id, records: map[uuid.UUID]guard.PluginApprovalRecord{id: approved}}}
	_, signed, open = e.waitStates([]uuid.UUID{id}, listed, one)
	require.False(t, signed, "product_b never answered: not yet signed for it")
	require.True(t, open)

	one["product_b"] = waitAgentRead{newest: id, records: map[uuid.UUID]guard.PluginApprovalRecord{id: approved}}
	_, signed, open = e.waitStates([]uuid.UUID{id}, listed, one)
	require.True(t, signed)
	require.True(t, open)

	gone := map[string]waitAgentRead{"product_a": {records: map[uuid.UUID]guard.PluginApprovalRecord{}}, "product_b": {records: map[uuid.UUID]guard.PluginApprovalRecord{}}}
	w, _, open = e.waitStates([]uuid.UUID{id}, listed, gone)
	require.False(t, open, "every agent answered and none shows it")
	require.Equal(t, stateNone, w[0].State)
}
