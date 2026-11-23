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
