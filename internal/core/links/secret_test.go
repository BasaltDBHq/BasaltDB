package links_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
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
}
