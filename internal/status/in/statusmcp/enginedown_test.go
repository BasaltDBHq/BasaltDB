package statusmcp

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/status"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// statusNow is the clock of every test; statusCredential is a credential
// file path no output may hold.
var statusNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

const statusCredential = "/etc/basalt/agents/bot.url"

// newCommands are the commands the engine builds for agent bot on linux
// (app's newCommands, which this package cannot reach): the inputs pass its
// checks, a valid agent name and an absolute or empty config path, so its
// result is guidance.NewCommands' own.
func newCommands(t *testing.T, configPath string) guidance.Commands {
	t.Helper()
	const name = "bot"
	require.True(t, config.ValidAgentName(name), name)
	require.True(t, configPath == "" || filepath.IsAbs(configPath), configPath)
	return guidance.NewCommands(name, configPath, config.DefaultPath("linux"), "linux", testManager())
}

func testManager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}

func testEngineHost() status.EngineHost {
	return status.EngineHost{
		LatestGuardVersion: guard.LatestVersion,
		ReadLastStop:       engine.ReadLastStop,
		StartHoldOffUntil: func(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool) {
			return laststop.StartHoldOffUntil(servicespec.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
		},
	}
}

func serveCall(t *testing.T, srv *mcpserver.Server, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, srv.ServeLine(context.Background(), &out, req))
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(out.String()), &resp), out.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &body))
	return body, resp.Result.IsError
}

func steps(t *testing.T, body map[string]any) []mcpcontract.StepKind {
	t.Helper()
	raw, err := json.Marshal(body["nextSteps"])
	require.NoError(t, err)
	var out []mcpcontract.StepKind
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestEngineDownToolsAnswerEveryCall(t *testing.T) {
	t.Parallel()
	cmds := newCommands(t, "/srv/basalt/engine.json")
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)

	served := make([]string, 0, len(down.Tools()))
	for _, tool := range down.Tools() {
		served = append(served, tool.Name)
	}
	sort.Strings(served)
	require.NoError(t, mcpcontract.CheckServed(mcpcontract.MustLoad(), served), "the shim lists exactly the IMPLEMENTED contracts")

	entry, ok := stepcatalogtest.CatalogOf(t).ErrorEntry(guidance.CodeUnavailable, guidance.ReasonEngineUnreachable, "query")
	require.True(t, ok)
	for _, tool := range served {
		if tool == guidance.ToolStatus {
			continue
		}
		body, isError := serveCall(t, srv, tool, map[string]any{})
		require.True(t, isError, tool)
		require.Equal(t, guidance.CodeUnavailable, body["code"], tool)
		require.Equal(t, guidance.ReasonEngineUnreachable, body["reason"], tool)
		require.NotEmpty(t, body["errorId"], tool)
		require.NotEmpty(t, body["personMessage"], tool)
		require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool)
		require.Equal(t, osservice.StartCommand("linux"), body["nextSteps"].([]any)[0].(map[string]any)["command"], tool)
	}
	body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, false, body["engine"].(map[string]any)["reachable"])
	require.Equal(t, guardmodel.GuardUnknown, body["guard"].(map[string]any)["state"])
	require.Equal(t, mcpcontract.OperatedByPerson, body["operatedBy"])

	body, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{"x": 1})
	require.True(t, isError)
	require.Equal(t, guidance.CodeInvalidArgument, body["code"])
	require.NotEmpty(t, body["nextSteps"])
}

// The shim reads operatedBy from the config: on an agent-operated engine the
// agent starts the engine itself, once, then repeats its call; the shim
// that cannot read the config keeps the person's steps (the default above).
func TestEngineDownOnAnAgentOperatedEngine(t *testing.T) {
	t.Parallel()
	cmds := newCommands(t, "")
	cfg := &config.Config{
		SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Mode: config.ModeService,
		Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}},
	}
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Config: cfg, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)

	v, ok := stepcatalogtest.CatalogOf(t).AgentOperatedEntry(mcpcontract.VariantError, guidance.CodeUnavailable, guidance.ReasonEngineUnreachable, "")
	require.True(t, ok)
	body, isError := serveCall(t, srv, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isError)
	require.Equal(t, v.Steps, steps(t, body))
	require.Nil(t, body["personMessage"], "the agent starts it: nothing for the person")
	first := body["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, osservice.StartCommand("linux"), first["command"])
	second := body["nextSteps"].([]any)[1].(map[string]any)
	require.Equal(t, "query", second["tool"])
	require.Equal(t, true, second["repeatCall"])

	body, isError = serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.False(t, isError)
	require.Equal(t, mcpcontract.OperatedByAgent, body["operatedBy"])
	p := body["problems"].([]any)[0].(map[string]any)
	require.Equal(t, mcpcontract.ActorAgent, p["nextSteps"].([]any)[0].(map[string]any)["actor"])
}

// A basalt mcp that tried to start the engine and could not says why in
// status and in every other call, with the log's path.
func TestEngineDownNamesWhyTheStartFailed(t *testing.T) {
	t.Parallel()
	cmds := newCommands(t, "")
	const why = "basalt mcp could not start the engine: the engine did not start within 15s. Its log is /s/engine.log."
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }, StartFailure: func() string { return why }}

	r, err := status.EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, why, "")
	require.NoError(t, err)
	require.Equal(t, "ENGINE_START_FAILED", r.Problems[0].Code, "the start failure comes first")
	require.Equal(t, why, r.Problems[0].Message)
	require.Equal(t, guidance.ReasonEngineUnreachable, r.Problems[1].Code, "the manual step stays")
	require.False(t, r.Ready)

	var query mcpserver.Tool
	for _, tool := range down.Tools() {
		if tool.Name == "query" {
			query = tool
		}
	}
	_, err = query.Call(context.Background(), json.RawMessage(`{}`))
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te)
	require.Contains(t, te.Message, why)

	// Without a failure nothing is added.
	r, err = status.EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Equal(t, guidance.ReasonEngineUnreachable, r.Problems[0].Code)
	require.Len(t, r.Problems, 1)
}

func TestEngineDownToolNamesHoldOff(t *testing.T) {
	t.Parallel()
	cmds := newCommands(t, "")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	at := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	rec, err := json.Marshal(servicespec.LastStopFileRecord{
		Reason: "the engine crashed 5 times within 10s; last: exit status 1",
		At:     at, EngineSHA256: laststop.HashEngineJSON(cfgPath),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.LastStopFile), rec, 0o600))
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
	now := at.Add(30 * time.Second)
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Config: cfg, ConfigPath: cfgPath, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}

	_, callErr := down.unreachable("query")(context.Background(), nil)
	require.Error(t, callErr)
	require.Contains(t, callErr.Error(), "the engine stopped and was not restarted: the engine crashed 5 times within 10s")
	require.Contains(t, callErr.Error(), "The next try is at 2026-11-21T08:01:00Z")
}

// An engine.json that exists and does not load is reported as such, with the
// load error and the file's own fix, never a service command, and operatedBy
// is not invented as PERSON (a same-user bot install has no service).
func TestEngineDownConfigThatDoesNotLoad(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		file       string
		wantErr    string
		operatedBy string
	}{
		"alpha.2 layout": {
			file:       `{"mode": "SAME_USER", "agents": [{"name": "bot", "credentialFile": "/home/bot/.basalt/bot.url"}]}`,
			wantErr:    "credentialFile",
			operatedBy: config.OperatedByUnknown,
		},
		"unknown key": {
			file:       `{"operatedBy": "AGENT", "bogusKey": 1}`,
			wantErr:    "bogusKey",
			operatedBy: mcpcontract.OperatedByAgent,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "engine.json")
			require.NoError(t, os.WriteFile(path, []byte(tc.file), 0o600))
			_, loadErr := config.Load(path)
			require.ErrorContains(t, loadErr, tc.wantErr)
			down := EngineDown{
				Host: testEngineHost(), Name: "bot", Commands: newCommands(t, path), ConfigErr: loadErr, ConfigPath: path,
				Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
			}
			srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)

			body, isError := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
			require.False(t, isError, "%v", body)
			require.Equal(t, tc.operatedBy, body["operatedBy"])
			require.Equal(t, false, body["ready"])
			problems := body["problems"].([]any)
			require.Len(t, problems, 1)
			p := problems[0].(map[string]any)
			require.Equal(t, guidance.ReasonConfigInvalid, p["code"])
			require.Contains(t, p["message"], tc.wantErr)
			requireNoServiceCommand(t, p)
			require.Contains(t, p["personMessage"], guidance.RemoveOldInstallDoc)
			require.Contains(t, p["personMessage"], "basalt init --agent bot --remote")

			body, isError = serveCall(t, srv, "query", map[string]any{})
			require.True(t, isError)
			require.Equal(t, guidance.ReasonEngineUnreachable, body["reason"])
			require.Contains(t, body["message"], tc.wantErr)
			requireNoServiceCommand(t, body)
		})
	}
}

func requireNoServiceCommand(t *testing.T, v map[string]any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	for _, bad := range []string{"systemctl", "launchctl", "basalt-engine.service", "RUN_COMMAND"} {
		require.NotContains(t, string(raw), bad)
	}
}

// A config file that is missing is not a config that failed to load.
func TestEngineDownMissingConfigKeepsTheStartStep(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	_, loadErr := config.Load(path)
	require.Error(t, loadErr)
	down := EngineDown{
		Host: testEngineHost(), Name: "bot", Commands: newCommands(t, path), ConfigErr: loadErr, ConfigPath: path,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)
	body, _ := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	require.Equal(t, guidance.ReasonEngineUnreachable, body["problems"].([]any)[0].(map[string]any)["code"])
}

// A service install's engine.json is 0600 for the service user: the agent's
// shim cannot read it, and that is a stopped engine, not a bad config.
func TestEngineDownUnreadableConfigKeepsTheStartStep(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"operatedBy": "PERSON"}`), 0o000))
	_, loadErr := config.Load(path)
	require.ErrorIs(t, loadErr, fs.ErrPermission)
	down := EngineDown{
		Host: testEngineHost(), Name: "bot", Commands: newCommands(t, path), ConfigErr: loadErr, ConfigPath: path,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)
	body, _ := serveCall(t, srv, guidance.ToolStatus, map[string]any{})
	p := body["problems"].([]any)[0].(map[string]any)
	require.Equal(t, guidance.ReasonEngineUnreachable, p["code"])
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	require.Contains(t, string(raw), "RUN_COMMAND", "the start step stays")

	body, isError := serveCall(t, srv, "query", map[string]any{})
	require.True(t, isError)
	require.Equal(t, guidance.ReasonEngineUnreachable, body["reason"])
	require.NotContains(t, body["message"], "cannot be loaded")
}

// A refused config's error quotes the value it refused: a credential in a
// URL never reaches the agent.
func TestEngineDownConfigErrorIsScrubbed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"operatedBy": "AGENT", "pagesUrl": "postgres://admin:hunter2@db:5432/app"}`), 0o600))
	_, loadErr := config.Load(path)
	require.Error(t, loadErr)
	down := EngineDown{
		Host: testEngineHost(), Name: "bot", Commands: newCommands(t, path), ConfigErr: loadErr, ConfigPath: path,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, down.Tools()...)
	for _, tool := range []string{guidance.ToolStatus, "query"} {
		body, _ := serveCall(t, srv, tool, map[string]any{})
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "hunter2", tool)
		require.Contains(t, string(raw), "cannot be loaded", tool)
	}
}
