package links_test

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

func pageSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Rotating moves an item's link to the page's secret: the old secret stops
// working, a relay link stays one with the new secret's token, and the old
// token is left for the caller (no drop is told).
func TestRotateMovesTheLinkToThePagesSecret(t *testing.T) {
	t.Parallel()
	s := links.NewSecrets(time.Now, rand.Reader)
	var dropped []channel.LinkToken
	s.OnDrop(func(tok channel.LinkToken) { dropped = append(dropped, tok) })
	id := uuid.Must(uuid.NewV7())
	expires := time.Now().Add(time.Hour)

	_, err := s.Rotate(id, pageSecret(t), expires)
	require.ErrorIs(t, err, links.ErrNoLiveLink)

	old, oldToken, err := s.IssueRelay(id, expires)
	require.NoError(t, err)
	_, err = s.Rotate(id, "not a secret", expires)
	require.ErrorIs(t, err, links.ErrBadSecret)
	require.True(t, s.Check(id, old), "a bad secret changes nothing")

	next := pageSecret(t)
	rot, err := s.Rotate(id, next, expires.Add(time.Hour))
	require.NoError(t, err)
	keys, err := channel.DeriveLink(next)
	require.NoError(t, err)
	require.Equal(t, links.Rotated{Relay: true, Token: keys.Token, OldToken: oldToken}, rot)
	require.False(t, s.Check(id, old))
	require.True(t, s.Check(id, next))
	require.Empty(t, dropped, "the session that rotated keeps its page socket")
	l, ok := s.Session(keys.Token)
	require.True(t, ok)
	require.Equal(t, id, l.Item)
	_, ok = s.Session(oldToken)
	require.False(t, ok, "the old token opens no session")

	local := uuid.Must(uuid.NewV7())
	_, err = s.Issue(local, expires)
	require.NoError(t, err)
	rot, err = s.Rotate(local, pageSecret(t), expires)
	require.NoError(t, err)
	require.False(t, rot.Relay)
}

// A reset revokes the link but keeps its hash until the revert expires,
// across a restart, so the page can say why it stopped working.
func TestResetKeepsTheRevokedLink(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "bot.links.json")
	s, err := links.OpenSecrets(path, clock, rand.Reader)
	require.NoError(t, err)
	id := uuid.Must(uuid.NewV7())
	secret, err := s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, s.Reset(id, now.Add(time.Hour)))
	require.False(t, s.Check(id, secret))
	require.True(t, s.WasReset(id, secret))
	require.False(t, s.WasReset(id, pageSecret(t)))
	require.False(t, s.WasReset(uuid.Must(uuid.NewV7()), secret))
	require.False(t, s.WasReset(id, ""))

	again, err := links.OpenSecrets(path, clock, rand.Reader)
	require.NoError(t, err)
	require.True(t, again.WasReset(id, secret), "the reset survives a restart")

	now = now.Add(2 * time.Hour)
	require.False(t, again.WasReset(id, secret), "forgotten once the revert expired")
}

// Revoking an item's link (a rejected revert) drops it whatever it is: a
// relay link's token is told, another item's link stays, and nothing is
// kept for WasReset.
func TestRevokeItemDropsItsLink(t *testing.T) {
	t.Parallel()
	s := links.NewSecrets(time.Now, rand.Reader)
	var dropped []channel.LinkToken
	s.OnDrop(func(tok channel.LinkToken) { dropped = append(dropped, tok) })
	expires := time.Now().Add(time.Hour)
	id, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	secret, token, err := s.IssueRelay(id, expires)
	require.NoError(t, err)
	kept, err := s.Issue(other, expires)
	require.NoError(t, err)

	require.NoError(t, s.RevokeItem(id))
	require.False(t, s.Check(id, secret))
	require.False(t, s.WasReset(id, secret), "a revoke is not a reset")
	require.Equal(t, []channel.LinkToken{token}, dropped)
	require.True(t, s.Check(other, kept))
	require.NoError(t, s.RevokeItem(id), "nothing left to revoke")
}
