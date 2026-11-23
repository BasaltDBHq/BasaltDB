package links_test

import (
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	corelinks "github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// A session resolves to the agent whose store holds the token, with its
// key; a token no store holds is not found.
func TestRegistrySessionNamesTheAgent(t *testing.T) {
	t.Parallel()
	r := links.NewRegistry(slog.New(slog.DiscardHandler))
	bot, ops := corelinks.NewSecrets(time.Now, rand.Reader), corelinks.NewSecrets(time.Now, rand.Reader)
	r.Add("bot", bot, func(channel.LinkToken) {})
	r.Add("ops", ops, func(channel.LinkToken) {})
	item := uuid.Must(uuid.NewV7())
	_, tok, err := ops.IssueRelay(item, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, r.Live(), 1)

	agent, l, ok := r.Session(tok)
	require.True(t, ok)
	require.Equal(t, "ops", agent)
	require.Equal(t, item, l.Item)
	require.NotEqual(t, channel.PSK{}, l.Keys.PSK)

	var unknown channel.LinkToken
	_, err = rand.Read(unknown[:])
	require.NoError(t, err)
	_, _, ok = r.Session(unknown)
	require.False(t, ok)
}
