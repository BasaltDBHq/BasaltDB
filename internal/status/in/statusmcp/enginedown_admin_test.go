package statusmcp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The engine-down tools (basalt mcp, engine not answering) refuse a call
// that holds an admin connection string too, and name nothing of it.
func TestEngineDownToolsRefuseAnAdminURL(t *testing.T) {
	t.Parallel()
	const secret = "s3cretpassw0rd"
	var logs bytes.Buffer
	url := "postgres://admin:" + secret + "@db.example.com:5432/app"
	entry, ok := stepcatalogtest.CatalogOf(t).ErrorEntry(guidance.CodeInvalidArgument, guidance.ReasonAdminCredential, "")
	require.True(t, ok)

	down := EngineDown{Host: testEngineHost(), Name: "bot", Log: slog.New(slog.NewTextHandler(&logs, nil)), Now: func() time.Time { return statusNow }}
	downTools := down.Tools()
	downSrv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(downTools, agent.WithMeta)...)
	for _, tool := range downTools {
		for _, args := range []map[string]any{{"sql": url}, {url: true}} {
			body, isError := serveCall(t, downSrv, tool.Name, args)
			require.True(t, isError, tool.Name)
			require.Equal(t, guidance.ReasonAdminCredential, body["reason"], tool.Name)
			require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			require.NotContains(t, string(raw), secret, tool.Name)
		}
	}
	require.NotContains(t, logs.String(), secret)
	require.NotContains(t, logs.String(), "db.example.com")
}
