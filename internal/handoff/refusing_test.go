package handoff_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// An engine started as root, or one whose key file is refused, never
// collects or reports an address.
func TestRefusingCollectors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		collector handoff.Collector
		want      error
	}{
		{handoff.RootCollector{}, handoff.ErrEngineAsRoot},
		{handoff.NoKeyCollector{}, handoff.ErrNoEngineKey},
	} {
		_, err := c.collector.Collect(ctx, "bot", "setup")
		require.ErrorIs(t, err, c.want)
		require.ErrorIs(t, c.collector.Report(ctx, "bot", "setup", setupcode.Address{}, handoff.Reach{}), c.want)
	}
}
