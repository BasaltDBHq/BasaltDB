package engine

import (
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestServerInfoNamesTheOperatorAndTheLocalPageOrigin(t *testing.T) {
	t.Parallel()
	info := agentEnv{cfg: config.Config{}, pagesOrigin: "http://localhost:8787"}.serverInfo(nil)
	require.Equal(t, mcpcontract.OperatedByPerson, info.OperatedBy, "an empty operatedBy is a person")
	require.Equal(t, "http://localhost:8787", info.PagesOrigin)

	info = agentEnv{cfg: config.Config{OperatedBy: mcpcontract.OperatedByAgent, DevLocalPages: true}, pagesOrigin: "http://localhost:8787"}.serverInfo(nil)
	require.Equal(t, mcpcontract.OperatedByAgent, info.OperatedBy)
	require.Equal(t, "http://localhost:8787", info.PagesOrigin, "the origin is sent as is; the shim opens nothing for AGENT")
}
