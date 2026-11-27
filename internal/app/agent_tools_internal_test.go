package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// postgresStore is a store of kind POSTGRES whose other methods these tests
// never call.
type postgresStore struct{ SQLStore }

func (postgresStore) Kind() action.StoreKind { return action.StorePostgres }

func (postgresStore) Capabilities() action.Capabilities {
	return action.Capabilities{InStoreSignatureCheck: true}
}

// TestServedToolsMatchTheContracts is the contract test for the served tool
// list (CONTRACT.md): every served tool has a contract, every IMPLEMENTED
// contract is served, and each tool lists its contract's schema.
func TestServedToolsMatchTheContracts(t *testing.T) {
	t.Parallel()
	contracts := mcpcontract.MustLoad()
	tools := AgentTools(NewService(testAgentDeps("bot", postgresStore{})))
	served := make([]string, 0, len(tools))
	for _, tool := range tools {
		served = append(served, tool.Name)
		c, ok := mcpcontract.Find(contracts, tool.Name)
		require.True(t, ok)
		require.Equal(t, c.InputSchema, tool.InputSchema, tool.Name)
		require.Equal(t, c.Description, tool.Description, tool.Name)
	}
	require.NoError(t, stepcatalogtest.CheckServed(contracts, served))
}

// TestServedToolListOrder pins the order of the tool list: it is what an agent
// reads in tools/list, so the per-domain lists must join in this order.
func TestServedToolListOrder(t *testing.T) {
	t.Parallel()
	tools := AgentTools(NewService(testAgentDeps("bot", postgresStore{})))
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	want := []string{
		"run_start", "query", "write", "run_history", "list_runs", "list_pending", "preview_revert", "revert_plan",
		"apply_revert_batch", "request_revert", "request_plugin", "withdraw", "describe", "status", "confirm_database",
	}
	require.Equal(t, want, names)
}

// driveStore is a store of kind DRIVE, which does not speak SQL.
type driveStore struct{ SQLStore }

func (driveStore) Kind() action.StoreKind { return action.StoreDrive }

func (driveStore) Capabilities() action.Capabilities {
	return action.Capabilities{InStoreSignatureCheck: true}
}

// TestServedToolListOrderWithoutSQL pins the tool list of a store that does
// not speak SQL: the same order, without query and write.
func TestServedToolListOrderWithoutSQL(t *testing.T) {
	t.Parallel()
	tools := AgentTools(NewService(testAgentDeps("bot", driveStore{})))
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	want := []string{
		"run_start", "run_history", "list_runs", "list_pending", "preview_revert", "revert_plan",
		"apply_revert_batch", "request_revert", "request_plugin", "withdraw", "describe", "status", "confirm_database",
	}
	require.Equal(t, want, names)
}

// TestAgentToolsNeedAService: the tool list of no service is a wiring
// defect.
func TestServedOrderRefusesAToolItDoesNotName(t *testing.T) {
	t.Parallel()
	require.PanicsWithValue(t, "agent: no served place for tool new_tool", func() {
		inServedOrder([]mcpserver.Tool{{Name: "status"}, {Name: "new_tool"}})
	})
}

func TestAgentToolsNeedAService(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { AgentTools(nil) })
}
