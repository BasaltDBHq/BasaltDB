//go:build linux || darwin

package main

// The plugin approval flow end to end, in same-user mode: the basalt plugin
// commands an agent runs, a real engine (engine.Run in this process) with
// its local pages, real guards in Postgres, a test passkey, and the test
// binary as the plugin (TestMain, testPluginFlag). Nothing here reaches
// into the engine: every check is what an agent, a person or the page can
// see (the commands' output, the status tool over the agent's socket, the
// page's routes over HTTP, the ledger in Postgres).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// The agents of a flow engine: the entries list the first two; the third
// is configured, on the same database, and never listed.
var flowListed = []string{"product_a", "product_b"}

const flowUnlisted = "product_c"

// flowWait bounds every wait on the running engine: a cold start of the
// test binary as a plugin under -race is slow.
const flowWait = 60 * time.Second

// flowEngine is a same-user engine on a real guard, run in this process
// with engine.Run, as a person runs basalt engine in the foreground.
type flowEngine struct {
	t          *testing.T
	base       string
	configPath string
	socketDir  string
	d          *guardtest.DB
	roles      map[string]*guardtest.Agent
	pk         *passkeytest.Authenticator
	// origin is the engine's local pages; empty on an agent-operated
	// engine, which uses the portal.
	origin string
	log    *lockedBuffer
	stop   func()
	// views are what the page's code showed for each approval it read.
	views map[string]pageView
}

func newFlowEngine(t *testing.T, operatedBy string) *flowEngine {
	t.Helper()
	// Short: macOS bounds Unix socket paths.
	dir, err := os.MkdirTemp("", "bpf")
	require.NoError(t, err)
	base, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	f := &flowEngine{
		t: t, base: base, configPath: filepath.Join(base, "config", "engine.json"), socketDir: filepath.Join(base, "run"),
		roles: map[string]*guardtest.Agent{}, log: &lockedBuffer{}, views: map[string]pageView{},
	}
	t.Cleanup(func() {
		if f.stop != nil {
			f.stop()
		}
		if t.Failed() {
			t.Logf("engine log:\n%s", f.log.String())
		}
		_ = os.RemoveAll(dir)
	})
	credDir := filepath.Join(base, "config", "agents")
	require.NoError(t, os.MkdirAll(credDir, 0o700))
	f.d = guardtest.New(t).WithDemo(t)
	me, err := user.Current()
	require.NoError(t, err)
	agents := make([]map[string]any, 0, len(flowListed)+1)
	for _, name := range append(slicesClone(flowListed), flowUnlisted) {
		a := f.d.NewAgent(t, name, []string{"public.leads"}, nil)
		f.roles[name] = a
		file := filepath.Join(credDir, name+".url")
		require.NoError(t, os.WriteFile(file, []byte(a.URL+"\n"), config.FileMode))
		agents = append(agents, map[string]any{"name": name, "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": file}})
	}
	cfg := map[string]any{
		"socketDir": f.socketDir, "stateDir": filepath.Join(base, "state"), "mode": "SAME_USER",
		"operatedBy": operatedBy, "updateCheck": "OFF", "agents": agents,
	}
	if operatedBy == mcpcontract.OperatedByAgent {
		cfg["pagesUrl"] = links.Portal // an agent-operated engine uses the portal
	} else {
		f.origin = "http://localhost:" + freePort(t)
		cfg["pagesUrl"] = f.origin
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, config.FileMode))
	f.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), f.d.Admin, f.pk.Credential(), "app"))
	return f
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// freePort is a loopback port nothing listens on now.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, l.Close())
	return port
}

// start runs the engine on the config as it is now, until stop or the end
// of the test, and waits until every agent's socket and the pages answer.
func (f *flowEngine) start() {
	f.t.Helper()
	t := f.t
	require.Nil(t, f.stop, "the engine is already running")
	cfg, err := config.Load(f.configPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = engine.Run(ctx, cfg, f.configPath, slog.New(slog.NewTextHandler(f.log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}()
	f.stop = func() {
		cancel()
		<-done
		f.stop = nil
		require.NoError(t, runErr)
	}
	stopped := func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	up := func() bool {
		if stopped() {
			return true
		}
		for _, name := range append(slicesClone(flowListed), flowUnlisted) {
			c, err := net.Dial("unix", config.SocketPath(f.socketDir, name))
			if err != nil {
				return false
			}
			_ = c.Close()
		}
		return f.origin == "" || osHost{}.PagesUp(context.Background(), f.origin)
	}
	require.Eventually(t, up, flowWait, 20*time.Millisecond)
	if stopped() {
		require.FailNow(t, "the engine stopped", "%v", runErr)
	}
}

func (f *flowEngine) restart() {
	f.t.Helper()
	f.stop()
	f.start()
}

// plugin runs basalt plugin args as the harness's caller: env is the whole
// environment the command sees (agentEnv for an agent), the real host, so
// the command reaches the running engine's pages as it would outside a
// test.
func (f *flowEngine) plugin(env map[string]string, args ...string) result {
	f.t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return env[k] })
	c.engine = engineAccess{unitInstalled: func() bool { return false }}
	code := runPlugin(c, append(args, "--config", f.configPath))
	return result{code, stdout.String(), stderr.String()}
}

// command runs a step's command line, "basalt plugin ...", as an agent.
func (f *flowEngine) command(line string) result {
	f.t.Helper()
	rest, ok := strings.CutPrefix(line, "basalt plugin ")
	require.True(f.t, ok, "a basalt plugin command: %q", line)
	args := strings.Fields(rest)
	// The step names --config with this engine's path; plugin adds it again.
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			require.Equal(f.t, shellQuote(f.configPath), args[i+1])
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	return f.plugin(agentEnv, args...)
}

func (f *flowEngine) config() config.Config {
	f.t.Helper()
	c, err := config.Load(f.configPath)
	require.NoError(f.t, err)
	return c
}

func (f *flowEngine) update(apply func(c *config.Config) error) {
	f.t.Helper()
	require.NoError(f.t, config.UpdateConfig(f.configPath, config.Change{Apply: apply}))
}

func (f *flowEngine) entry(instance string) func(c *config.Config) *config.Plugin {
	return func(c *config.Config) *config.Plugin {
		i := c.PluginIndex(plugin.EntryKey{Name: "acme-ner", Instance: instance})
		require.GreaterOrEqual(f.t, i, 0, instance)
		return &c.Plugins[i]
	}
}

// source writes an unsigned local plugin acme-ner at version whose command
// is this test binary, started with testPluginFlag and extra.
func (f *flowEngine) source(version string, extra ...string) string {
	f.t.Helper()
	t := f.t
	dir, err := os.MkdirTemp(f.base, "src-")
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bin"), 0o755))
	exe, err := os.Executable()
	require.NoError(t, err)
	in, err := os.Open(exe)
	require.NoError(t, err)
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(dir, "bin", "acme-ner"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	require.NoError(t, err)
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	args, err := json.Marshal(append([]string{testPluginFlag}, extra...))
	require.NoError(t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": %q, "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner", "args": %s } },
  "files": { "bin/acme-ner": "sha256:%x" },
  "network": { "egress": [] }
}
`, version, args, h.Sum(nil))
	require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))
	return dir
}

// remoteSource writes an unsigned remote plugin acme-cloud at url.
func (f *flowEngine) remoteSource(url, hostPort string) string {
	f.t.Helper()
	dir, err := os.MkdirTemp(f.base, "src-")
	require.NoError(f.t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-cloud", "version": "2.0.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "remote": { "transport": "connectrpc", "url": %q } },
  "network": { "egress": [%q] }
}
`, url, hostPort)
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, plugin.ManifestFile), []byte(manifest), 0o644))
	return dir
}

// opened checks an add or enable succeeded and returns its approval result,
// which must open exactly one approval on this engine's one database.
func (f *flowEngine) opened(r result) (approvalResult, approvalItem) {
	f.t.Helper()
	require.Equal(f.t, exitOK, r.code, r.stdout+r.stderr)
	res := approvalResultOf(f.t, r)
	require.Len(f.t, res.Approvals, 1, r.stdout)
	a := res.Approvals[0]
	require.Nil(f.t, a.Refused, r.stdout)
	return res, a
}

// shortSecret is the secret of a short link to the plugin page on the
// engine's local pages.
func (f *flowEngine) shortSecret(a approvalItem) string {
	f.t.Helper()
	secret, ok := strings.CutPrefix(a.URL, f.origin+"/plugins/"+a.ApprovalID+"#s=")
	require.True(f.t, ok, "a short link on the local pages: %q", a.URL)
	return secret
}

// pageRequest is what the page reads for a short link: GET
// /api/v1/plugins/{id} with the link's secret, over HTTP to the running
// engine.
func (f *flowEngine) pageRequest(a approvalItem) (approval.PluginRequest, approval.PluginBinding) {
	f.t.Helper()
	code, body := f.pageCall(http.MethodGet, "/api/v1/plugins/"+a.ApprovalID, f.shortSecret(a), "")
	require.Equal(f.t, http.StatusOK, code, body)
	var req approval.PluginRequest
	require.NoError(f.t, json.Unmarshal([]byte(body), &req))
	require.Equal(f.t, a.ApprovalID, req.ApprovalID.String())
	b, err := req.Check()
	require.NoError(f.t, err, "the binding parses and the settings hash to settingsSha256")
	requireBindingSchema(f.t, req.Binding)
	if v, ok := runPage(f.t, "request", body); ok {
		require.Equal(f.t, a.ApprovalID, v.ApprovalID)
		require.Equal(f.t, req.Settings, v.Settings, "the page shows the settings once they match")
		f.views[a.ApprovalID] = v
	}
	return req, b
}

// pageView is what the page's own code makes of a request: its level, the
// tick at level 3, its sentences in order and the settings it shows.
type pageView struct {
	ApprovalID string   `json:"approvalId"`
	Level      int      `json:"level"`
	Tick       *string  `json:"tick"`
	Sentences  []string `json:"sentences"`
	Settings   string   `json:"settings"`
}

// runPage runs testdata/plugin_page.mjs under node: the page's checks and
// view on input. Without node it reports false, except on CI, where the
// check job installs node and the page must run.
func runPage(t *testing.T, kind, input string) (pageView, bool) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		require.Empty(t, os.Getenv("CI"), "node is not installed; the page's code cannot run")
		t.Log("node is not installed: the page's own code is not run")
		return pageView{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), flowWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "testdata/plugin_page.mjs", kind, input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "the page refused the request: %s", stderr.String())
	var v pageView
	require.NoError(t, json.Unmarshal(out, &v), string(out))
	return v, true
}

// pageSays: when the page's code ran for approval a, it shows level and,
// in order, the sentences want among its own.
func (f *flowEngine) pageSays(a approvalItem, level int, want ...string) {
	f.t.Helper()
	v, ok := f.views[a.ApprovalID]
	if !ok {
		return
	}
	require.Equal(f.t, level, v.Level, v.Sentences)
	require.Equal(f.t, level == 3, v.Tick != nil, "the tick is level 3's only")
	i := 0
	for _, s := range v.Sentences {
		if i < len(want) && s == want[i] {
			i++
		}
	}
	require.Equal(f.t, len(want), i, "want, in order, %q among %q", want, v.Sentences)
}

func (f *flowEngine) pageCall(method, path, secret, body string) (int, string) {
	f.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.origin+path, strings.NewReader(body))
	require.NoError(f.t, err)
	if secret != "" {
		req.Header.Set(links.SecretHeader, secret)
	}
	if method == http.MethodPost {
		// The page posts from its own origin.
		req.Header.Set("Origin", f.origin)
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(f.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(f.t, err)
	return resp.StatusCode, string(raw)
}

// signed is the person's passkey response to binding.
func (f *flowEngine) signed(req approval.PluginRequest) approval.PluginApprovalResponse {
	f.t.Helper()
	as, err := f.pk.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(f.t, err)
	return approval.NewPluginApprovalResponse(req.ApprovalID, as)
}

// relay posts the person's signature through the page's relay route, as
// the page does on a short link.
func (f *flowEngine) relay(a approvalItem, resp approval.PluginApprovalResponse) (int, string) {
	f.t.Helper()
	body, err := json.Marshal(resp)
	require.NoError(f.t, err)
	return f.pageCall(http.MethodPost, "/api/v1/plugins/"+a.ApprovalID+"/approve", f.shortSecret(a), string(body))
}

// paste is the code the page shows on a long link, which the person pastes
// into the chat and the agent runs basalt plugin approve with.
func (f *flowEngine) paste(req approval.PluginRequest) string {
	f.t.Helper()
	code, err := f.signed(req).Code()
	require.NoError(f.t, err)
	require.True(f.t, strings.HasPrefix(code, approval.PluginResponsePrefix), code)
	return code
}

func (f *flowEngine) ledgerCount(agentName, kind string) int {
	f.t.Helper()
	var n int
	// Plain SQL: a fixture read of the guard's own table.
	require.NoError(f.t, f.d.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM basalt_meta.ledger WHERE agent = $1 AND kind = $2`, f.roles[agentName].Role, kind).Scan(&n))
	return n
}

// lastEvent is the detail of the newest ledger row of kind for name/instance
// in the agent's ledger, nil when there is none.
func (f *flowEngine) lastEvent(agentName, kind, name, instance string) map[string]any {
	f.t.Helper()
	var raw []byte
	// Plain SQL: a fixture read of the guard's own table.
	err := f.d.Admin.QueryRow(context.Background(), `SELECT detail::text FROM basalt_meta.ledger
		WHERE agent = $1 AND kind = $2 AND detail->>'name' = $3 AND detail->>'instance' = $4 ORDER BY seq DESC LIMIT 1`,
		f.roles[agentName].Role, kind, name, instance).Scan(&raw)
	if err != nil {
		require.ErrorContains(f.t, err, "no rows")
		return nil
	}
	var d map[string]any
	require.NoError(f.t, json.Unmarshal(raw, &d))
	return d
}

// listState is basalt plugin list's approval state of an entry for agent.
func (f *flowEngine) listState(instance, agentName string) string {
	f.t.Helper()
	r := f.plugin(agentEnv, "list", "--json")
	require.Equal(f.t, exitOK, r.code, r.stderr)
	var out struct {
		Plugins []listedEntry `json:"plugins"`
	}
	require.NoError(f.t, json.Unmarshal([]byte(r.stdout), &out))
	for _, p := range out.Plugins {
		if p.Instance != instance {
			continue
		}
		for _, a := range p.Approval.Agents {
			if a.Agent == agentName {
				return a.State
			}
		}
	}
	return ""
}

// callTool calls tool on the running engine over the agent's socket, as
// the agent's MCP client does, and returns the tool's text and whether it
// is an error.
func (f *flowEngine) callTool(agentName, tool string) (string, bool) {
	f.t.Helper()
	conn, err := net.Dial("unix", config.SocketPath(f.socketDir, agentName))
	require.NoError(f.t, err)
	defer conn.Close()
	require.NoError(f.t, conn.SetDeadline(time.Now().Add(flowWait)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`)
	require.NoError(f.t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(f.t, err)
	line, err := r.ReadString('\n')
	require.NoError(f.t, err)
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	require.NoError(f.t, json.Unmarshal([]byte(line), &resp), line)
	require.Empty(f.t, resp.Error, line)
	require.NotEmpty(f.t, resp.Result.Content, line)
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func (f *flowEngine) status(agentName string) agent.StatusReport {
	f.t.Helper()
	text, isErr := f.callTool(agentName, "status")
	require.False(f.t, isErr, text)
	var st agent.StatusReport
	require.NoError(f.t, json.Unmarshal([]byte(text), &st), text)
	return st
}

// pluginProblem is the status problem of entry name/instance for the
// agent, nil when status reports none.
func (f *flowEngine) pluginProblem(agentName, name, instance string) *agent.Problem {
	f.t.Helper()
	prefix := "plugin " + name + "/" + instance + " "
	for _, p := range f.status(agentName).Problems {
		if strings.HasPrefix(p.Message, prefix) {
			return &p
		}
	}
	return nil
}

// waitProblem waits until the agent's status reports code for the entry
// (the engine checks plugins as it starts them) and returns the problem.
func (f *flowEngine) waitProblem(agentName, name, instance, code string) agent.Problem {
	f.t.Helper()
	var last *agent.Problem
	ok := waitFor(func() bool {
		last = f.pluginProblem(agentName, name, instance)
		return last != nil && last.Code == code
	})
	require.True(f.t, ok, "%s: want %s for %s/%s, last %+v", agentName, code, name, instance, last)
	return *last
}

// waitServed waits until the agent's status reports no problem at all for
// acme-ner/instance: it is served and its plugin answers READY.
func (f *flowEngine) waitServed(agentName, instance string) {
	const name = "acme-ner"
	f.t.Helper()
	var last *agent.Problem
	ok := waitFor(func() bool {
		last = f.pluginProblem(agentName, name, instance)
		return last == nil
	})
	require.True(f.t, ok, "%s: want %s/%s served and ready, last %+v", agentName, name, instance, last)
}

func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(flowWait)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// requireNotBlocked: a tool call that does not touch plugins answers as
// usual for the agent.
func (f *flowEngine) requireNotBlocked(agentName string) {
	f.t.Helper()
	text, isErr := f.callTool(agentName, "list_runs")
	require.False(f.t, isErr, "a withheld plugin blocks none of the agent's calls: %s", text)
}

// stepCommand is the command of the first step of action in steps whose
// command starts with prefix.
func stepCommand(t *testing.T, steps []agent.NextStep, actor, prefix string) string {
	t.Helper()
	for _, s := range steps {
		if s.Actor == actor && strings.HasPrefix(s.Command, prefix) {
			return s.Command
		}
	}
	require.FailNow(t, "no step", "%s %q in %+v", actor, prefix, steps)
	return ""
}

// bindingSchema is api/plugin/approval/binding.schema.json with the plugin
// schemas it refers to, loaded as the contract test loads them.
var bindingSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	const base = "https://basaltvault.app/schemas/plugin/"
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		return regexp.Compile(regexp.MustCompile(`\{([0-9]+),[0-9]{4,}\}`).ReplaceAllString(ecmaEscape.ReplaceAllString(s, `\x{$1}`), `{$1,}`))
	})
	for _, f := range []string{"manifest.schema.json", "config.schema.json", "events.schema.json", "approval/binding.schema.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "api", "plugin", f))
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if err := c.AddResource(base+f, doc); err != nil {
			return nil, err
		}
	}
	return c.Compile(base + "approval/binding.schema.json")
})

// requireBindingSchema: the binding text passes binding.schema.json, as the
// page checks before it shows anything.
func requireBindingSchema(t *testing.T, binding string) {
	t.Helper()
	s, err := bindingSchema()
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(binding))
	require.NoError(t, err)
	require.NoError(t, s.Validate(inst), binding)
}

// pageLevel is the page's level of a binding as CONTRACT.md (The plugin
// approval page, The level) gives it, written out here from the contract's
// words rather than taken from the command's code.
func pageLevel(t *testing.T, b approval.PluginBinding) int {
	t.Helper()
	var endpoint struct {
		Kind string `json:"kind"`
	}
	require.NoError(t, json.Unmarshal(b.Endpoint, &endpoint))
	var isolation struct {
		Files string `json:"files"`
	}
	if len(b.Isolation) > 0 {
		require.NoError(t, json.Unmarshal(b.Isolation, &isolation))
	}
	switch {
	case b.Signer == "KNOWN":
		return 1
	case endpoint.Kind == "REMOTE" || isolation.Files == "OS_USER":
		return 2
	case endpoint.Kind == "LOCAL" && isolation.Files == "NONE":
		return 3
	}
	require.FailNow(t, "no level for the binding", "%+v", b)
	return 0
}

// requireApproved: n more PLUGIN_APPROVED rows than before for each
// listed agent, and none for the unlisted one.
func (f *flowEngine) requireApproved(before map[string]int, n int) {
	f.t.Helper()
	for _, name := range flowListed {
		require.Equal(f.t, before[name]+n, f.ledgerCount(name, string(guard.PluginApproved)), name)
	}
	require.Zero(f.t, f.ledgerCount(flowUnlisted, string(guard.PluginApproved)), "the approval names only the listed agents")
}

func (f *flowEngine) approvedCounts() map[string]int {
	f.t.Helper()
	out := map[string]int{}
	for _, name := range flowListed {
		out[name] = f.ledgerCount(name, string(guard.PluginApproved))
	}
	return out
}

// requireServedEvent: the engine's newest PLUGIN_ENABLED for the entry in
// each listed agent's ledger carries signer UNKNOWN and no key id, and the
// unlisted agent has none.
func (f *flowEngine) requireServedEvent(name, instance string) {
	f.t.Helper()
	for _, a := range flowListed {
		d := f.lastEvent(a, "PLUGIN_ENABLED", name, instance)
		require.NotNil(f.t, d, "%s: the engine recorded the entry served", a)
		require.Equal(f.t, "UNKNOWN", d["signer"], a)
		require.NotContains(f.t, d, "signerKeyId", a)
	}
	require.Nil(f.t, f.lastEvent(flowUnlisted, "PLUGIN_ENABLED", name, instance), "never served to an agent the entry does not list")
}

// TestPluginApprovalFlowLocal runs the flow for an unsigned local plugin
// that two of three agents use: an agent's add, the engine withholding it,
// the page's routes, a settings change reopened from status's own step,
// the signature relayed by the page, a restart that serves it, then
// disable and enable needing a new signature, which comes back as a pasted
// code, also when the two happen between two engine starts.
func TestPluginApprovalFlowLocal(t *testing.T) {
	f := newFlowEngine(t, "")
	const name, inst = "acme-ner", plugin.DefaultInstance
	f.start()
	src := f.source("1.4.0")

	// 1. An agent adds an unsigned plugin: a link, the entry written, and
	// nothing served after the engine starts on it.
	res, a1 := f.opened(f.plugin(agentEnv, "add", src, "--agents", strings.Join(flowListed, ","), "--json"))
	f.shortSecret(a1)
	require.Equal(t, flowListed, a1.Agents)
	require.Equal(t, []mcp.Link{{Label: "Approve the plugin acme-ner", URL: a1.URL}}, res.Links)
	require.Contains(t, res.PersonMessage, levelUnknownHere, "the level 3 warning goes to the person")
	p := f.config().Plugins[0]
	require.True(t, p.Enabled)
	require.Equal(t, config.PluginApprovalRequired, p.Approval)
	require.Equal(t, flowListed, p.Agents)
	require.Equal(t, 1, f.ledgerCount("product_a", string(guard.PluginApprovalPending)))
	require.Equal(t, "PENDING", f.listState(inst, "product_a"))

	f.restart()
	for _, ag := range flowListed {
		pr := f.waitProblem(ag, name, inst, agent.ProblemPluginAwaitingApproval)
		require.Contains(t, pr.Message, "waiting for a person to sign it", ag)
		f.requireNotBlocked(ag)
	}
	require.Nil(t, f.pluginProblem(flowUnlisted, name, inst), "not listed: nothing to report")
	f.requireNotBlocked(flowUnlisted)
	for _, ag := range append(slicesClone(flowListed), flowUnlisted) {
		require.Nil(t, f.lastEvent(ag, "PLUGIN_ENABLED", name, inst), "%s: withheld, never recorded served", ag)
	}

	// 2. The page's routes on the running engine answer for the link: the
	// binding parses, passes its schema, and is level 3.
	code, html := f.pageCall(http.MethodGet, "/plugins/"+a1.ApprovalID, "", "")
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, html, "<html")
	req1, b1 := f.pageRequest(a1)
	require.Equal(t, 3, pageLevel(t, b1))
	require.Equal(t, pluginLevel(b1), pageLevel(t, b1), "the command's level is the page's")
	require.Equal(t, "UNKNOWN", b1.Signer)
	require.Empty(t, b1.SignerKeyID)
	require.Equal(t, []string{f.roles["product_a"].Role, f.roles["product_b"].Role}, b1.Agents)
	require.Equal(t, f.roles["product_a"].Role, b1.RequestedBy)
	require.Equal(t, p.ManifestSHA256, b1.ManifestSHA256)
	require.Equal(t, "{}", req1.Settings, "no settings yet")
	require.Empty(t, b1.Change, "a first approval")
	require.Equal(t, []passkey.Bytes{f.pk.ID}, req1.CredentialIDs)
	f.pageSays(a1, 3, levelUnknownHere, "I know who made this plugin and I trust them with my data.",
		"It says it needs no network. That is not enforced on the computer Basalt runs on.",
		"It reads the text your agents send to the AI provider, before Basalt hides private values in it.",
		"Used for: product_a, product_b.", "Asked by product_a.")

	// The person (or agent) gives the plugin settings, here a call deadline
	// a cold start fits in and a config: a settings change. The engine's
	// own step for the waiting plugin opens the new approval; the old link
	// can no longer be signed.
	mc := 0.60
	f.update(func(c *config.Config) error {
		e := f.entry(inst)(c)
		e.TimeoutMs, e.MinConfidence = config.MaxPluginTimeoutMs, &mc
		e.Config = json.RawMessage(`{"threshold": 0.60, "max": 1e3, "langs": ["en", "id"]}`)
		return nil
	})
	f.restart()
	pr := f.waitProblem("product_a", name, inst, agent.ProblemPluginAwaitingApproval)
	reopen := stepCommand(t, pr.NextSteps, mcp.ActorPerson, "basalt plugin enable ")
	require.Contains(t, reopen, "--approve-with-passkey")
	_, a2 := f.opened(f.command(reopen))
	require.NotEqual(t, a1.ApprovalID, a2.ApprovalID)
	code, body := f.relay(a1, f.signed(req1))
	require.Equal(t, http.StatusConflict, code, "the first approval was cancelled: %s", body)
	req2, b2 := f.pageRequest(a2)
	require.Equal(t, 3, pageLevel(t, b2))
	require.NotEqual(t, b1.SettingsSHA256, b2.SettingsSHA256)
	require.Contains(t, req2.Settings, `"threshold": 0.60`, "config is kept as written")
	require.Contains(t, req2.Settings, `"max": 1000`, "1e3 reads 1000")
	f.pageSays(a2, 3, levelUnknownHere)

	// 3. The person signs on the page; the page relays it.
	before := f.approvedCounts()
	code, body = f.relay(a2, f.signed(req2))
	require.Equal(t, http.StatusOK, code, body)
	f.requireApproved(before, 1)
	for _, ag := range flowListed {
		require.Equal(t, "APPROVED", f.listState(inst, ag), ag)
	}
	code, body = f.relay(a2, f.signed(req2))
	require.Equal(t, http.StatusConflict, code, "signed once: %s", body)

	// 4. After a restart the plugin is served to the listed agents, and the
	// ledger holds the approval and the engine's record with the signer.
	f.restart()
	for _, ag := range flowListed {
		f.waitServed(ag, inst)
		f.requireNotBlocked(ag)
	}
	f.requireServedEvent(name, inst)
	approved := f.lastEvent("product_a", string(guard.PluginApproved), name, inst)
	require.NotNil(t, approved)
	require.Equal(t, a2.ApprovalID, approved["approvalId"])
	require.Equal(t, b2.SettingsSHA256, approved["settingsSha256"])
	require.Equal(t, "UNKNOWN", approved["signer"])

	// 5. disable, then enable: withheld until a new approval is signed.
	r := f.plugin(agentEnv, "disable", name)
	require.Equal(t, exitOK, r.code, r.stderr)
	f.restart()
	for _, ag := range flowListed {
		require.Nil(t, f.pluginProblem(ag, name, inst), "%s: disabled, so not configured for it", ag)
		// The engine writes its plugin records beside serving: wait for it.
		require.True(t, waitFor(func() bool { return f.lastEvent(ag, "PLUGIN_DISABLED", name, inst) != nil }),
			"%s: the engine recorded it off", ag)
		require.Equal(t, "ENDED", f.listState(inst, ag), "%s: turning it off ended the approval", ag)
	}
	res3, a3 := f.opened(f.plugin(agentEnv, "enable", name, "--json"))
	require.Contains(t, res3.PersonMessage, "asks you to approve a change to the plugin acme-ner 1.4.0.")
	f.restart()
	for _, ag := range flowListed {
		f.waitProblem(ag, name, inst, agent.ProblemPluginAwaitingApproval)
	}
	req3, b3 := f.pageRequest(a3)
	require.JSONEq(t, `{}`, string(b3.Change), "the same entry turned on again")
	f.pageSays(a3, 3, "You approved acme-ner before, and it was turned off. Turning it on again needs your approval.", levelUnknownHere)

	// The signature comes back the other way: the person pastes the code
	// the page shows into the chat, and the agent runs basalt plugin
	// approve with it.
	before = f.approvedCounts()
	r = f.plugin(agentEnv, "approve", f.paste(req3), "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out approvedJSON
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, a3.ApprovalID, out.ApprovalID)
	require.Equal(t, "APPROVED", out.Status)
	f.requireApproved(before, 1)
	require.Equal(t, "APPROVED", f.listState(inst, "product_b"))
	f.restart()
	for _, ag := range flowListed {
		f.waitServed(ag, inst)
	}
	require.Equal(t, a3.ApprovalID, f.lastEvent("product_a", string(guard.PluginApproved), name, inst)["approvalId"])

	// The same with disable and enable back to back, between two starts:
	// the signed approval no longer serves it.
	require.Equal(t, exitOK, f.plugin(agentEnv, "disable", name).code)
	_, a4 := f.opened(f.plugin(agentEnv, "enable", name, "--json"))
	f.restart()
	for _, ag := range flowListed {
		f.waitProblem(ag, name, inst, agent.ProblemPluginAwaitingApproval)
	}
	req4, _ := f.pageRequest(a4)
	code, body = f.relay(a4, f.signed(req4))
	require.Equal(t, http.StatusOK, code, body)
	f.restart()
	for _, ag := range flowListed {
		f.waitServed(ag, inst)
	}
}

// TestPluginApprovalFlowRemote: the same flow for an unsigned remote
// plugin at a loopback HTTPS server. Its level is 2; once signed, the
// engine serves it and dials the server.
func TestPluginApprovalFlowRemote(t *testing.T) {
	f := newFlowEngine(t, "")
	var dials atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			dials.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	hostPort := net.JoinHostPort("localhost", port)
	const name, inst = "acme-cloud", plugin.DefaultInstance

	f.start()
	res, a := f.opened(f.plugin(agentEnv, "add", f.remoteSource("https://"+hostPort, hostPort), "--agents", strings.Join(flowListed, ","), "--json"))
	require.Contains(t, res.PersonMessage, levelUnknown, "the level 2 warning")
	require.NotContains(t, res.PersonMessage, levelUnknownHere)
	f.restart()
	for _, ag := range flowListed {
		f.waitProblem(ag, name, inst, agent.ProblemPluginAwaitingApproval)
		f.requireNotBlocked(ag)
	}
	require.Zero(t, dials.Load(), "a withheld remote plugin is never dialed")

	req, b := f.pageRequest(a)
	require.Equal(t, 2, pageLevel(t, b))
	require.Equal(t, pluginLevel(b), pageLevel(t, b))
	require.JSONEq(t, fmt.Sprintf(`{"kind": "REMOTE", "host": %q}`, hostPort), string(b.Endpoint))
	require.Empty(t, b.Isolation, "isolation is LOCAL only")
	require.Equal(t, []string{hostPort}, b.Egress)
	f.pageSays(a, 2, levelUnknown, "It runs at "+hostPort+". Everything it sees is sent there.",
		"Basalt cannot check what runs there or where it sends things next.", "Used for: product_a, product_b.")

	require.Zero(t, dials.Load(), "still never dialed while withheld")
	before := f.approvedCounts()
	r := f.plugin(agentEnv, "approve", f.paste(req))
	require.Equal(t, exitOK, r.code, r.stderr)
	f.requireApproved(before, 1)
	require.Equal(t, "APPROVED", f.listState(inst, "product_a"))

	f.restart()
	require.True(t, waitFor(func() bool { return dials.Load() > 0 }), "the engine dials the served remote plugin")
	for _, ag := range flowListed {
		// The server's certificate is httptest's own, which the engine does
		// not trust, so the plugin never gets READY; what is proven is that
		// the approval matched and the entry was served and dialed.
		pr := f.waitProblem(ag, name, inst, agent.ProblemPluginUnavailable)
		require.Contains(t, pr.Message, "is not ready", ag)
		require.NotContains(t, pr.Message, "not served to this agent", ag)
	}
	f.requireServedEvent(name, inst)
}

// TestPluginApprovalTampered: a signed and served entry changed behind the
// approval is withheld at the next start. Each case is its own instance of
// the plugin on one engine.
func TestPluginApprovalTampered(t *testing.T) {
	f := newFlowEngine(t, "")
	const name = "acme-ner"
	cases := []string{"settings", "swapped", "repinned", "version"}
	f.start()
	src := f.source("1.4.0")
	for _, inst := range cases {
		f.opened(f.plugin(agentEnv, "add", src, "--agents", strings.Join(flowListed, ","), "--instance", inst, "--json"))
		f.update(func(c *config.Config) error {
			f.entry(inst)(c).TimeoutMs = config.MaxPluginTimeoutMs
			return nil
		})
		_, a := f.opened(f.plugin(agentEnv, "enable", name, "--instance", inst, "--json"))
		req, _ := f.pageRequest(a)
		code, body := f.relay(a, f.signed(req))
		require.Equal(t, http.StatusOK, code, body)
	}
	f.restart()
	for _, inst := range cases {
		for _, ag := range flowListed {
			f.waitServed(ag, inst)
		}
	}
	ts, err := plugin.NewTrustStore(plugin.ModeSameUser, runtime.GOOS, filepath.Dir(f.configPath))
	require.NoError(t, err)
	root, err := plugin.Root(plugin.ModeSameUser, runtime.GOOS, filepath.Dir(f.configPath))
	require.NoError(t, err)

	// settings: engine.json's settings changed after signing.
	f.update(func(c *config.Config) error {
		f.entry("settings")(c).Config = json.RawMessage(`{"threshold": 0.9}`)
		return nil
	})
	// swapped: another copy's files put in place of the pinned copy, the
	// pin in engine.json left as it was.
	other := f.source("1.4.0", "variant=2")
	pinned := f.entry("swapped")(ptrConfig(f.config())).ManifestSHA256
	pinnedDir := filepath.Join(root, name, "swapped", pinned)
	require.DirExists(t, pinnedDir)
	require.NoError(t, os.Chmod(pinnedDir, 0o755))
	for _, file := range []string{plugin.ManifestFile, filepath.Join("bin", "acme-ner")} {
		raw, err := os.ReadFile(filepath.Join(other, file))
		require.NoError(t, err)
		dst := filepath.Join(pinnedDir, file)
		require.NoError(t, os.Chmod(filepath.Dir(dst), 0o755))
		require.NoError(t, os.Remove(dst))
		require.NoError(t, os.WriteFile(dst, raw, 0o755))
	}
	// repinned: another copy of the same version installed beside it and
	// engine.json pointed at it, as an agent with the engine's file access
	// could.
	// version: a different version of the plugin added to the entry the
	// same way.
	for inst, src := range map[string]string{"repinned": other, "version": f.source("2.0.0")} {
		v, err := plugin.Install(src, root, inst, ts, plugin.ModeSameUser, plugin.RequireApproval(true))
		require.NoError(t, err)
		f.update(func(c *config.Config) error {
			f.entry(inst)(c).ManifestSHA256 = v.ManifestSHA256
			return nil
		})
	}

	f.restart()
	want := map[string][]string{
		"settings": {"settingsSha256"},
		"repinned": {"manifestSha256"},
		"version":  {"version", "manifestSha256"},
	}
	for inst, fields := range want {
		for _, ag := range flowListed {
			pr := f.waitProblem(ag, name, inst, agent.ProblemPluginApprovalMismatch)
			_, differ, ok := strings.Cut(pr.Message, "these differ: ")
			require.True(t, ok, pr.Message)
			differ, _, _ = strings.Cut(differ, ". ")
			require.ElementsMatch(t, fields, strings.Split(differ, ", "), "%s %s: exactly what changed", inst, ag)
			require.NotContains(t, pr.Message, "0.9", "a mismatch never names a value")
			require.True(t, waitFor(func() bool { return f.lastEvent(ag, "PLUGIN_DISABLED", name, inst) != nil }),
				"%s %s: the engine records it no longer served", inst, ag)
		}
	}
	// The swapped copy no longer verifies against its pin, so it is refused
	// before any approval is read: the contract's PLUGIN_NOT_TRUSTED.
	for _, ag := range flowListed {
		f.waitProblem(ag, name, "swapped", agent.ProblemPluginNotTrusted)
	}

	// A mismatch ended the approval: changing it back needs a new one.
	f.update(func(c *config.Config) error {
		f.entry("settings")(c).Config = nil
		return nil
	})
	f.restart()
	for _, ag := range flowListed {
		pr := f.waitProblem(ag, name, "settings", agent.ProblemPluginAwaitingApproval)
		require.Contains(t, pr.Message, "ended", ag)
		require.Equal(t, "ENDED", f.listState("settings", ag), ag)
	}

	// The honest way to a new version, the command, opens a new approval;
	// the old signature does not serve the new copy.
	f.opened(f.plugin(agentEnv, "add", f.source("2.1.0"), "--agents", strings.Join(flowListed, ","), "--instance", "version", "--json"))
	f.restart()
	for _, ag := range flowListed {
		pr := f.waitProblem(ag, name, "version", agent.ProblemPluginAwaitingApproval)
		require.Contains(t, pr.Message, "waiting for a person to sign it", ag)
	}
}

func ptrConfig(c config.Config) *config.Config { return &c }

// TestPluginApprovalFlowAgentOperated: on an engine an agent operates, the
// agent's add hands over a portal link and the next steps make the restart
// the agent's; the engine withholds the plugin until the pasted code is
// approved and the agent restarts it.
func TestPluginApprovalFlowAgentOperated(t *testing.T) {
	f := newFlowEngine(t, mcpcontract.OperatedByAgent)
	const name, inst = "acme-ner", plugin.DefaultInstance
	f.start()
	res, a := f.opened(f.plugin(agentEnv, "add", f.source("1.4.0"), "--agents", strings.Join(flowListed, ","), "--json"))
	require.True(t, strings.HasPrefix(a.URL, links.Portal+"/plugins/"+a.ApprovalID+"#"), a.URL)
	require.NotEmpty(t, res.NextSteps)
	last := res.NextSteps[len(res.NextSteps)-1]
	require.Equal(t, mcp.ActorAgent+" "+mcp.ActionRunCommand, last.Actor+" "+last.Action)
	require.Contains(t, last.Command, "basalt engine", "the restart is the agent's step")
	for _, s := range res.NextSteps {
		require.NotEqual(t, mcp.ActorPerson+" "+mcp.ActionRunCommand, s.Actor+" "+s.Action, "the person runs no command: %+v", s)
	}
	require.NotContains(t, res.PersonMessage, "basalt ", "no command for the person")
	require.Equal(t, config.PluginApprovalRequired, f.config().Plugins[0].Approval)

	f.restart()
	for _, ag := range flowListed {
		pr := f.waitProblem(ag, name, inst, agent.ProblemPluginAwaitingApproval)
		stepCommand(t, pr.NextSteps, mcp.ActorAgent, "basalt plugin enable ")
		f.requireNotBlocked(ag)
	}

	// The portal link is a long link: the page reads the texts from it, and
	// the person pastes the code it shows into the chat.
	req, b := requestOf(t, a.URL)
	require.Equal(t, 3, pageLevel(t, b))
	_, frag, _ := strings.Cut(a.URL, "#")
	if v, ok := runPage(t, "fragment", frag); ok {
		f.views[a.ApprovalID] = v
	}
	f.pageSays(a, 3, levelUnknownHere, "Asked by product_a.")
	r := f.plugin(agentEnv, "approve", f.paste(req))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, "APPROVED", f.listState(inst, "product_a"))
	f.restart()
	f.waitServedEvent(name, inst)
	for _, ag := range flowListed {
		f.requireServedNotWithheld(ag, name, inst)
	}
}

// waitServedEvent waits until the engine recorded the entry served for
// every listed agent, then checks those records (requireServedEvent). The
// engine writes them before it starts any plugin.
func (f *flowEngine) waitServedEvent(name, instance string) {
	f.t.Helper()
	require.True(f.t, waitFor(func() bool {
		for _, a := range flowListed {
			if f.lastEvent(a, "PLUGIN_ENABLED", name, instance) == nil {
				return false
			}
		}
		return true
	}), "the engine records %s/%s served", name, instance)
	f.requireServedEvent(name, instance)
}

// requireServedNotWithheld: once the engine recorded the entry served
// (waitServedEvent), status reports no problem for it, or only that its
// plugin, which has no settings for a cold start here, is not ready yet.
func (f *flowEngine) requireServedNotWithheld(agentName, name, instance string) {
	f.t.Helper()
	var last *agent.Problem
	ok := waitFor(func() bool {
		last = f.pluginProblem(agentName, name, instance)
		return last == nil || (last.Code == agent.ProblemPluginUnavailable && strings.Contains(last.Message, "is not ready"))
	})
	require.True(f.t, ok, "%s: want %s/%s served, last %+v", agentName, name, instance, last)
}
