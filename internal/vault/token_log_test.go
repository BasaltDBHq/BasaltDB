package vault_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/vault"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// lockedBuffer is a log sink the client's goroutines can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestLinkTokensAreNotLogged: a link token is a bearer handle at the Vault,
// so the warnings about a refused, conflicting or failed link name the
// item, never the token (CWE-532).
func TestLinkTokensAreNotLogged(t *testing.T) {
	t.Parallel()
	limited, conflicting := newToken(t), newToken(t)
	v := vaulttest.New(vaulttest.Options{OnRegister: func(_ string, m vaulttest.RegisterLink) vaulttest.Verdict {
		if m.LinkToken == limited.Wire() {
			return vaulttest.Verdict{Code: vaulttest.ErrLinkLimit}
		}
		return vaulttest.Verdict{}
	}})
	t.Cleanup(v.Close)
	v.Bind(conflicting.Wire(), otherEngine, time.Now().Add(time.Hour))
	limitedItem, conflictItem := uuid.New(), uuid.New()
	live := &liveLinks{links: []vault.Link{
		{Token: limited, Item: limitedItem, ExpiresAt: time.Now().Add(time.Hour)},
		{Token: conflicting, Item: conflictItem, ExpiresAt: time.Now().Add(time.Hour)},
	}}
	var logs lockedBuffer
	opts := fastOptions(v.URL(), newKeys(t))
	opts.Links = live
	opts.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := connected(t, opts)

	require.Eventually(t, func() bool { return len(live.conflicts()) == 1 }, waitFor, tick)
	require.Eventually(t, func() bool {
		out := logs.String()
		return strings.Contains(out, "LINK_LIMIT") && strings.Contains(out, conflictItem.String())
	}, waitFor, tick)
	c.Unregister(conflicting) // answered LINK_CONFLICT: a warning
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "unregistering a link was refused")
	}, waitFor, tick)
	require.NoError(t, c.Register(context.Background(), newToken(t), time.Now().Add(time.Hour)))

	out := logs.String()
	require.Contains(t, out, limitedItem.String(), "the refused link is named by its item")
	for _, tok := range []string{limited.Wire(), conflicting.Wire()} {
		require.NotContains(t, out, tok)
	}
	require.NotContains(t, out, "linkToken")
}
