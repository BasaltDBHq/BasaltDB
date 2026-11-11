package links_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

func TestSecrets(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	s := links.NewSecrets(func() time.Time { return now }, rand.Reader)
	id := uuid.Must(uuid.NewV7())

	first, err := s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, first, 22, "128 bits, base64url without padding")
	require.True(t, s.Check(id, first))
	require.False(t, s.Check(id, ""), "no secret")
	wrong := []byte(first)
	wrong[0] ^= 1
	require.False(t, s.Check(id, string(wrong)), "wrong secret")
	require.False(t, s.Check(uuid.Must(uuid.NewV7()), first), "another item")

	second, err := s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.False(t, s.Check(id, first), "a new link revokes the earlier one")
	require.True(t, s.Check(id, second))

	now = now.Add(time.Hour)
	require.False(t, s.Check(id, second), "expires with the held item")
}

func TestLinkHelpers(t *testing.T) {
	t.Parallel()
	link := links.WithSecret("http://localhost:8787/approvals/x", "abc")
	require.Equal(t, "http://localhost:8787/approvals/x#s=abc", link)
	require.Equal(t, "abc", links.SecretOf(link))
	require.Empty(t, links.SecretOf("http://localhost:8787/approvals/x#1.data"), "a long link has none")
	require.Empty(t, links.SecretOf("http://localhost:8787/approvals/x"))

	binding := `{"kind": "APPROVE"}`
	proof := links.IssueProof(binding)
	require.True(t, links.ProofMatches(binding, proof))
	require.False(t, links.ProofMatches(binding+" ", proof))
	challenge := sha256.Sum256([]byte(binding))
	require.False(t, links.ProofMatches(binding, hex.EncodeToString(challenge[:])), "the passkey challenge is not a proof")
}

func TestSecretsPersist(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "bot.links.json")

	s, err := links.OpenSecrets(path, clock, rand.Reader)
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
	again, err := links.OpenSecrets(path, clock, rand.Reader)
	require.NoError(t, err)
	require.True(t, again.Check(id, secret), "a short link survives a restart")
	_, err = again.Issue(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	raw, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), gone.String(), "pruned with the held item's expiry")

	// A damaged file is reported; the store starts empty and replaces it.
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	broken, err := links.OpenSecrets(path, clock, rand.Reader)
	require.Error(t, err)
	require.False(t, broken.Check(id, secret))
	_, err = broken.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	_, err = links.OpenSecrets(path, clock, rand.Reader)
	require.NoError(t, err)
}
