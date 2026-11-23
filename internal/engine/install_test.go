package engine_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

func TestCrashLoops(t *testing.T) {
	t.Parallel()
	require.True(t, engine.CrashLoops(2, 1))
	require.False(t, engine.CrashLoops(1, 1), "the first exit: the service manager has not started it again yet")
	require.False(t, engine.CrashLoops(3, 0), "a clean exit, a restart")
	require.False(t, engine.CrashLoops(1, -1))
}
