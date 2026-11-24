package plugin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

func TestUserClash(t *testing.T) {
	t.Parallel()
	long := "acme-ner-presidio"
	others := []pluginmodel.EntryKey{{Name: long, Instance: "default"}, {Name: "acme-ner", Instance: "client_x"}}
	require.Nil(t, plugin.UserClash(long, "default", others), "an entry does not clash with itself")
	require.Nil(t, plugin.UserClash("other", "default", others))
}

func TestPluginNetwork(t *testing.T) {
	t.Parallel()
	require.Equal(t, "ENFORCED", plugin.PluginNetwork("linux", nil))
	require.Equal(t, "DECLARED", plugin.PluginNetwork("linux", []string{"hooks.slack.com:443"}))
	require.Equal(t, "NOT_ENFORCED", plugin.PluginNetwork("darwin", nil))
}
