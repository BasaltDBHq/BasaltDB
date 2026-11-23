package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

func TestEnginePathIsAbsolute(t *testing.T) {
	t.Parallel()
	require.Equal(t, "/home/me/basalt-m4/engine.json", engine.EnginePath("/home/me/basalt-m4/engine.json"))
	abs, err := filepath.Abs("engine.json")
	require.NoError(t, err)
	require.Equal(t, abs, engine.EnginePath("engine.json"), "a relative path works from any directory")
}
