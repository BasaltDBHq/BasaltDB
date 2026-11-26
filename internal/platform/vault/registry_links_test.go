package vault

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	corelinks "github.com/basaltdbhq/basaltdb/internal/core/links"
)

func TestLinksOfKeepsTokenItemAndExpiry(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	l := corelinks.RelayLink{Token: channel.LinkToken{1}, Item: uuid.Must(uuid.NewV7()), ExpiresAt: at}
	require.Equal(t, []Link{{Token: l.Token, Item: l.Item, ExpiresAt: at}}, LinksOf([]corelinks.RelayLink{l}))
	require.Empty(t, LinksOf(nil))
}

func TestSessionOfCopiesTheKeyAndNamesTheAgent(t *testing.T) {
	t.Parallel()
	l := corelinks.SessionLink{Item: uuid.Must(uuid.NewV7()), Keys: channel.LinkKeys{Token: channel.LinkToken{2}, PSK: channel.PSK{3}}}
	got, ok := SessionOf("bot", l, true)
	require.True(t, ok)
	require.Equal(t, SessionLink{Token: l.Keys.Token, Agent: "bot", Item: l.Item, PSK: channel.PSK{3}}, got)
	got, ok = SessionOf("", l, false)
	require.False(t, ok)
	require.Equal(t, SessionLink{}, got)
}
