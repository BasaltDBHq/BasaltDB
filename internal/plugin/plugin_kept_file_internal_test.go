package plugin

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestUnusableEntriesFileProblemNamesTheFile: the problem for an entries
// file the engine cannot use names no entry and carries the file, so its
// steps move that file aside and restart the engine.
func TestUnusableEntriesFileProblemNamesTheFile(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	r := f.run(os.Geteuid(), nil)
	require.NoError(t, os.WriteFile(f.s.store.EntriesPath(), []byte("not json"), 0o600))
	r.ep.applyNow(context.Background())

	require.Eventually(t, func() bool {
		for _, p := range r.ep.pluginProblems("product_a") {
			if p.Code == problemPluginUnavailable && p.Name == "" {
				require.Equal(t, f.s.store.EntriesPath(), p.File)
				require.False(t, p.EngineKept)
				return true
			}
		}
		return false
	}, keptWait, 50*time.Millisecond)
}
