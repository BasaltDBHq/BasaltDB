package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigArg(t *testing.T) {
	t.Parallel()
	_, given := configArg([]string{"--agent", "bot"})
	require.False(t, given)
	for want, args := range map[string][]string{
		"/a.json": {"--config", "/a.json"},
		"/b.json": {"-config=/b.json"},
		"/c.json": {"--config=/a.json", "--agent", "x", "-config", "/c.json"},
		"/d.json": {"--config=/d.json", "--", "--config", "/e.json"},
	} {
		got, given := configArg(args)
		require.True(t, given, args)
		require.Equal(t, want, got, args)
	}
}
