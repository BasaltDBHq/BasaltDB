package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigArg(t *testing.T) {
	t.Parallel()
	for want, args := range map[string][]string{
		"def":     {"--agent", "bot"},
		"/a.json": {"--config", "/a.json"},
		"/b.json": {"-config=/b.json"},
		"/c.json": {"--config=/a.json", "--agent", "x", "-config", "/c.json"},
		"/d.json": {"--config=/d.json", "--", "--config", "/e.json"},
	} {
		require.Equal(t, want, configArg(args, "def"), args)
	}
}
