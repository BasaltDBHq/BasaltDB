package statusmcp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// A request the engine took and never answered is answered with an error,
// never run again: a tools/call with UNAVAILABLE ENGINE_UNREACHABLE, any
// other request with a JSON-RPC error, and a notification with nothing.
func TestAnswerAbandonedNeverRunsTheCallAgain(t *testing.T) {
	t.Parallel()
	down := EngineDown{Host: testEngineHost(), Name: "bot", Commands: newCommands(t, ""), Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow }}
	answer := func(line string) map[string]json.RawMessage {
		var out bytes.Buffer
		require.NoError(t, down.AnswerAbandoned(&out, []byte(line)))
		if out.Len() == 0 {
			return nil
		}
		var resp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out.Bytes(), &resp), out.String())
		return resp
	}

	require.Nil(t, answer(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))

	resp := answer(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	require.Contains(t, string(resp["error"]), engine.AbandonedMessage)

	resp = answer(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write","arguments":{}}}`)
	var result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	require.NoError(t, json.Unmarshal(resp["result"], &result))
	require.True(t, result.IsError)
	var te toolresult.ToolError
	require.NoError(t, json.Unmarshal([]byte(result.Content[0].Text), &te))
	require.Equal(t, guidance.CodeUnavailable, te.Code)
	require.Equal(t, guidance.ReasonEngineUnreachable, te.Reason)
}

// basalt mcp given a socket whose name is no agent name keeps that name and
// builds its commands for the fallback agent; a missing config is kept as
// the error status reports.
func TestLoadEngineDownFallsBackToAnAgentName(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	down, err := LoadEngineDown("not an agent!", path, osservice.Manager(), testEngineHost(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Equal(t, "not an agent!", down.Name)
	require.Equal(t, fallbackAgentName, down.Commands.AgentName())
	require.Nil(t, down.Config)
	require.Error(t, down.ConfigErr)

	_, err = LoadEngineDown("bot", "relative/engine.json", osservice.Manager(), testEngineHost(), slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "must be absolute")
}
