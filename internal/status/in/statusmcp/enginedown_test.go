package statusmcp

import (
	"context"
	"encoding/json"
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
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/status"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// statusNow is the clock of every test; statusCredential is a credential
// file path no output may hold.
var statusNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

const statusCredential = "/etc/basalt/agents/bot.url"

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
	cmds, err := agent.NewCommands("bot", "/srv/basalt/engine.json", "linux", testManager())
	require.NoError(t, err)
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(down.Tools(), agent.WithMeta)...)

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
	cmds, err := agent.NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	cfg := &config.Config{
		SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Mode: config.ModeService,
		Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}},
	}
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Config: cfg, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(down.Tools(), agent.WithMeta)...)

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
	cmds, err := agent.NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	const why = "basalt mcp could not start the engine: the engine did not start within 15s. Its log is /s/engine.log."
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: cmds, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }, StartFailure: func() string { return why }}

	r, err := status.EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, why, "")
	require.NoError(t, err)
	require.Equal(t, "ENGINE_START_FAILED", r.Problems[0].Code, "the start failure comes first")
	require.Equal(t, why, r.Problems[0].Message)
	require.Equal(t, guidance.ReasonEngineUnreachable, r.Problems[1].Code, "the manual step stays")
	require.False(t, r.Ready)

	var query guidance.Tool
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
	cmds, err := agent.NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
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
