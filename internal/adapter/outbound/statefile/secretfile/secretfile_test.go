package secretfile_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/secretfile"
)

func TestSecretsPersist(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "bot.links.json")

	s, err := secretfile.Open(path, clock, rand.Reader)
	require.NoError(t, err, "no file yet")
	id, gone := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	secret, err := s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	_, err = s.Issue(gone, now.Add(time.Minute))
	require.NoError(t, err)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), secret, "hashes only, never a secret")

	// The engine restarts: the link still works, the expired item is pruned.
	now = now.Add(2 * time.Minute)
	again, err := secretfile.Open(path, clock, rand.Reader)
	require.NoError(t, err)
	require.True(t, again.Check(id, secret), "a short link survives a restart")
	_, err = again.Issue(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	raw, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), gone.String(), "pruned with the held item's expiry")

	// A damaged file is reported; the store starts empty and replaces it.
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	broken, err := secretfile.Open(path, clock, rand.Reader)
	require.Error(t, err)
	require.False(t, broken.Check(id, secret))
	_, err = broken.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	_, err = secretfile.Open(path, clock, rand.Reader)
	require.NoError(t, err)
}
