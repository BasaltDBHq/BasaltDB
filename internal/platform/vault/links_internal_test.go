package vault

import (
	"context"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault/vaulttest"
)

type fixedLinks []Link

func (f fixedLinks) Live() []Link               { return f }
func (fixedLinks) Conflict(_ channel.LinkToken) {}

func randomToken(t *testing.T) channel.LinkToken {
	t.Helper()
	var tok channel.LinkToken
	_, err := rand.Read(tok[:])
	require.NoError(t, err)
	return tok
}

// A Vault that never answers an UNREGISTER_LINK or a REGISTER_LINK sent
// again after READY leaves no request waiting past RegisterTimeout.
func TestPendingStaysBoundedWithASilentVault(t *testing.T) {
	t.Parallel()
	silent := func(string, vaulttest.RegisterLink) vaulttest.Verdict { return vaulttest.Verdict{Drop: true} }
	v := vaulttest.New(vaulttest.Options{
		OnRegister:   silent,
		OnUnregister: func(string, vaulttest.UnregisterLink) vaulttest.Verdict { return vaulttest.Verdict{Drop: true} },
	})
	t.Cleanup(v.Close)
	live := make(fixedLinks, 0, 20)
	for range 20 {
		live = append(live, Link{Token: randomToken(t), ExpiresAt: time.Now().Add(time.Hour)})
	}
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	c, err := New(Options{
		URL: v.URL(), Keys: keys, Log: slog.New(slog.DiscardHandler), PingInterval: time.Hour,
		RegisterTimeout: 100 * time.Millisecond, Links: live,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, c.Connected, 5*time.Second, 5*time.Millisecond)

	for range 30 {
		c.Unregister(randomToken(t))
	}
	cn := c.current()
	require.NotNil(t, cn)
	require.Positive(t, cn.pendingLen(), "the fire-and-forget requests wait for a while")
	require.Eventually(t, func() bool { return cn.pendingLen() == 0 }, 5*time.Second, 5*time.Millisecond,
		"and are forgotten after RegisterTimeout")
}

func TestRegisterSendsExpiryInWholeSecondsRoundedDown(t *testing.T) {
	t.Parallel()
	tok := randomToken(t)
	zone := time.FixedZone("UTC+7", 7*60*60)
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 11, 12, 10, 0, 0, 999_999_999, time.UTC), "2026-11-12T10:00:00Z"},
		{time.Date(2026, 11, 12, 10, 0, 0, 1, time.UTC), "2026-11-12T10:00:00Z"},
		{time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), "2026-11-12T10:00:00Z"},
		{time.Date(2026, 11, 12, 17, 0, 59, 500_000_000, zone), "2026-11-12T10:00:59Z"},
	} {
		m := registerMsg(1, tok, tc.at)
		require.Equal(t, tc.want, m.ExpiresAt, tc.at.String())
		got, err := time.Parse(time.RFC3339, m.ExpiresAt)
		require.NoError(t, err)
		require.False(t, got.After(tc.at), "never after the link's own expiry")
	}

	// A sub-second expiry goes through the Vault as it is.
	v := vaulttest.New(vaulttest.Options{})
	t.Cleanup(v.Close)
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	c, err := New(Options{URL: v.URL(), Keys: keys, Log: slog.New(slog.DiscardHandler), PingInterval: time.Hour})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, c.Connected, 5*time.Second, 5*time.Millisecond)
	expires := time.Now().Add(time.Hour).Truncate(time.Second).Add(700 * time.Millisecond)
	require.NoError(t, c.Register(context.Background(), tok, expires))
	owner, ok := v.LinkOwner(tok.Wire())
	require.True(t, ok)
	require.Equal(t, keys.EngineID(), owner)
}
