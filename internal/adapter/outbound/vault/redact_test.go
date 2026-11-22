package vault_test

import (
	"bytes"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// TestLinkTokensRedactInLogs: a token logged as itself, or in a vault.Link
// or links.RelayLink, never prints, in text or JSON logs; Wire is the wire
// form.
func TestLinkTokensRedactInLogs(t *testing.T) {
	t.Parallel()
	var tok channel.LinkToken
	_, err := rand.Read(tok[:])
	require.NoError(t, err)
	item := uuid.New()
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var out bytes.Buffer
		log := slog.New(h(&out))
		log.Info("token", "linkToken", tok)
		log.Info("link", "link", vault.Link{Token: tok, Item: item, ExpiresAt: at})
		log.Info("relay", "link", links.RelayLink{Token: tok, Item: item, ExpiresAt: at})
		require.NotContains(t, out.String(), tok.Wire(), name)
		require.Contains(t, out.String(), "[redacted]", name)
		require.Contains(t, out.String(), item.String(), "%s: a link is named by its item", name)
	}
	parsed, err := channel.ParseLinkToken(tok.Wire())
	require.NoError(t, err)
	require.Equal(t, tok, parsed, "Wire is the wire form")
}
