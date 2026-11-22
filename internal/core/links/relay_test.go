package links_test

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/statefile/secretfile"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// dropLog records the tokens a store tells OnDrop.
type dropLog struct {
	mu  sync.Mutex
	got []channel.LinkToken
}

func (d *dropLog) add(t channel.LinkToken) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, t)
}

func (d *dropLog) take() []channel.LinkToken {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.got
	d.got = nil
	return out
}

func TestIssueRelayKeepsTheDerivedTokenAndPSK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "bot.links.json")
	s, err := secretfile.Open(path, clock, rand.Reader)
	require.NoError(t, err)
	id := uuid.Must(uuid.NewV7())

	secret, token, err := s.IssueRelay(id, now.Add(time.Hour))
	require.NoError(t, err)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	require.Equal(t, keys.Token, token, "the token is HKDF(secret, basalt-vault-link.1)")
	require.True(t, s.Check(id, secret), "a relay link is a short link like any other")
	require.Equal(t, []links.RelayLink{{Token: token, Item: id, ExpiresAt: now.Add(time.Hour)}}, s.Relay())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), token.Wire(), "the token is kept next to the hash")
	require.Contains(t, string(raw), base64.RawURLEncoding.EncodeToString(keys.PSK[:]), "and so is the psk")
	require.NotContains(t, string(raw), secret, "never the secret")

	// The engine restarts: the relay link is still live and registered again.
	again, err := secretfile.Open(path, clock, rand.Reader)
	require.NoError(t, err)
	require.True(t, again.Check(id, secret))
	require.Equal(t, s.Relay(), again.Relay())

	// A local link is no relay link.
	_, err = again.Issue(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, again.Relay(), 1)
}

func TestRelayLinksTellOnDrop(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	s := links.NewSecrets(clock, rand.Reader)
	var drops dropLog
	s.OnDrop(drops.add)
	id, other := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())

	_, first, err := s.IssueRelay(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.Empty(t, drops.take())

	_, second, err := s.IssueRelay(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, []channel.LinkToken{first}, drops.take(), "a reissue drops the earlier link's token")

	require.NoError(t, s.Revoke(id, first))
	require.Empty(t, drops.take(), "a revoke of an older token leaves the newer link alone")
	require.Len(t, s.Relay(), 1)

	require.NoError(t, s.Revoke(id, second))
	require.Equal(t, []channel.LinkToken{second}, drops.take())
	require.Empty(t, s.Relay())

	_, third, err := s.IssueRelay(id, now.Add(time.Hour))
	require.NoError(t, err)
	_, err = s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, []channel.LinkToken{third}, drops.take(), "a local link that replaces a relay link drops its token")
	_, err = s.Issue(id, now.Add(time.Hour))
	require.NoError(t, err)
	require.Empty(t, drops.take(), "a local link has no token")

	_, fourth, err := s.IssueRelay(other, now.Add(time.Minute))
	require.NoError(t, err)
	held, err := s.RevokeToken(channel.LinkToken{1})
	require.NoError(t, err)
	require.False(t, held)
	held, err = s.RevokeToken(fourth)
	require.NoError(t, err)
	require.True(t, held, "a LINK_CONFLICT revokes the link of its token")
	require.Empty(t, s.Relay())
	require.Empty(t, drops.take(), "without unregistering it: the token is another engine's")

	_, fifth, err := s.IssueRelay(other, now.Add(time.Minute))
	require.NoError(t, err)
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	s.Prune()
	require.Equal(t, []channel.LinkToken{fifth}, drops.take(), "an expired link drops its token")
	s.Prune()
	require.Empty(t, drops.take(), "once")

	_, a, err := s.IssueRelay(other, now.Add(time.Hour))
	require.NoError(t, err)
	_, b, err := s.IssueRelay(uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, s.RevokeRelay())
	require.ElementsMatch(t, []channel.LinkToken{a, b}, drops.take(), "rotation revokes every relay link")
	require.Empty(t, s.Relay())
}

func TestOpenSecretsRefusesABadRelayEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "bot.links.json")
	hash := "00000000000000000000000000000000000000000000000000000000000000aa"
	for name, entry := range map[string]string{
		"a token without its psk": `"linkToken": "AAAAAAAAAAAAAAAAAAAAAA"`,
		"a psk without its token": `"psk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
		"a short psk":             `"linkToken": "AAAAAAAAAAAAAAAAAAAAAA", "psk": "AAAA"`,
		"a bad token":             `"linkToken": "!", "psk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
	} {
		file := `{"links": [{"id": "` + uuid.Must(uuid.NewV7()).String() + `", "hash": "` + hash +
			`", "expiresAt": "2026-11-12T08:00:00Z", ` + entry + `}]}`
		require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
		s, err := secretfile.Open(path, clock, rand.Reader)
		require.Error(t, err, name)
		require.Empty(t, s.Relay(), name)
	}
}
