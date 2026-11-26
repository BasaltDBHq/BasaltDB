package handoff_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

type memoryCacheFile struct{ raw []byte }

func (m *memoryCacheFile) Read() (string, error) {
	if m.raw == nil {
		return "", errors.New("no file")
	}
	return string(m.raw), nil
}

func (m *memoryCacheFile) Write(raw []byte) error {
	m.raw = raw
	return nil
}

// The cache keeps one setup's probe: another setup, or no file, is none.
func TestFileCacheKeepsOneSetup(t *testing.T) {
	t.Parallel()
	c := handoff.NewFileCache(&memoryCacheFile{})
	_, ok := c.Load("a")
	require.False(t, ok)
	require.NoError(t, c.Save(handoff.Cached{SetupID: "a", Reason: "NO_ROUTE"}))
	got, ok := c.Load("a")
	require.True(t, ok)
	require.Equal(t, "NO_ROUTE", got.Reason)
	_, ok = c.Load("b")
	require.False(t, ok)
}

// A cache without its file is refused when it is built.
func TestNewFileCacheRefusesNoFile(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { handoff.NewFileCache(nil) })
}
