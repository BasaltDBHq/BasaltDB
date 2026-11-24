package plugin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Which engines keep plugin entries of their own, and whose agents may
// change them: a service engine the person's users; an agent-operated
// engine on the bot's computer its own user, which every agent runs as. A
// person-operated engine that runs as the person keeps none, so
// request_plugin answers SAME_USER_MODE there (persona 1, unchanged).
func TestPluginCallers(t *testing.T) {
	t.Parallel()
	const euid = 501
	service := config.Config{Mode: config.ModeService, PersonUIDs: []uint32{1000}}
	require.True(t, plugin.KeepsEntries(service))
	require.Equal(t, []uint32{1000}, plugin.Callers(service, euid))

	bot := config.Config{OperatedBy: mcpcontract.OperatedByAgent}
	require.True(t, plugin.KeepsEntries(bot))
	require.Equal(t, []uint32{euid}, plugin.Callers(bot, euid))

	require.False(t, plugin.KeepsEntries(config.Config{}), "a person's own same-user engine keeps no plugins")
	require.False(t, plugin.KeepsEntries(config.Config{OperatedBy: mcpcontract.OperatedByPerson}))
}
