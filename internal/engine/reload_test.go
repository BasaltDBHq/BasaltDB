package engine_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// A reload asked for while the engine waits makes the restart trigger
// return, and marks it a reload.
func TestUpgradeOrReload(t *testing.T) {
	t.Parallel()
	reload, reloading := make(chan struct{}, 1), make(chan struct{})
	up := engine.UpgradeOrReload(nil, reload, reloading)
	reload <- struct{}{}
	require.NoError(t, up(t.Context()))
	select {
	case <-reloading:
	default:
		t.Fatal("not marked a reload")
	}
}
