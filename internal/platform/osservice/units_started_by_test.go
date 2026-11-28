package osservice

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// The unit's --started-by value is the engine's own StartedByService, so
// status reports SERVICE for what the unit starts.
func TestUnitStartedByIsTheEnginesService(t *testing.T) {
	t.Parallel()
	require.Equal(t, engine.StartedByService, startedByService)
}
