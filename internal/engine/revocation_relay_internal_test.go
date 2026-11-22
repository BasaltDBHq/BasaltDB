package engine

import (
	"context"
	"crypto/rand"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/store/postgres"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
	"github.com/basaltdbhq/basaltdb/internal/vault/vaulttest"
)

// closeCodes records the codes the engine closes page sessions with, as
// the Vault passes them to the page.
type closeCodes struct {
	mu    sync.Mutex
	codes []websocket.StatusCode
}

func (c *closeCodes) hook(_ vaulttest.SessionInfo, dir vaulttest.Direction, code websocket.StatusCode) (websocket.StatusCode, bool) {
	if dir == vaulttest.ToPage {
		c.mu.Lock()
		c.codes = append(c.codes, code)
		c.mu.Unlock()
	}
	return code, true
}

func (c *closeCodes) has(code websocket.StatusCode) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.codes, code)
}

// The person revokes the engine in their database while a page holds a
// relay session: at the engine's next read of its record (a heartbeat) the
// session closes with ENGINE_REVOKED, the link opens no new session, the
// agent's next held write carries the long link, and the engine, which
// serves no other database, leaves the Vault.
func TestRevokedEngineEndsItsRelaySessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	leads := []string{"public.leads"}
	bot := d.NewAgent(t, "bot", leads, leads)

	stateDir := t.TempDir()
	keys, err := channel.LoadOrCreateKeys(filepath.Join(stateDir, channel.KeyFileName), time.Now)
	require.NoError(t, err)
	_, err = guard.RecordEngine(ctx, d.Admin, keys.PublicKeySPKI())
	require.NoError(t, err)
	pool, err := postgres.NewPool(ctx, bot.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	read := func(ctx context.Context, id string) (*guard.RecordedEngine, error) {
		return guard.EngineRecord(ctx, pool, id)
	}

	// The engine as run.go wires it.
	secrets := links.NewSecrets(time.Now, rand.Reader)
	rev := newRevocation(keys.EngineID(), quietLog())
	late := &lateRelay{}
	svc := newPGAgent(t, bot.URL, 4).service(func(dp *agent.Deps) {
		dp.PagesBase, dp.Links, dp.Receipts, dp.Poll = links.Portal, secrets, keys, relayPoll
		dp.Relay = revocableRelay{next: late, revoked: func() bool { return rev.isRevoked("bot") }}
	})
	closes := &closeCodes{}
	v := vaulttest.New(vaulttest.Options{OnSessionClose: closes.hook})
	t.Cleanup(v.Close)
	live := newRelayLinks(quietLog())
	site := pages.New(links.Portal, quietLog())
	site.Add(svc)
	cfg := config.Config{Vault: config.VaultOn, PagesURL: links.Portal, VaultURL: v.URL()}
	ev := openVault(cfg, stateDir, time.Now, quietLog(), live, site)
	require.NotNil(t, ev.client)
	live.watch(rev, endRevoked(ev.client))
	rev.add("bot", read, secrets)
	live.add("bot", secrets, ev.client.Unregister)
	require.False(t, rev.check(ctx, "bot"), "the record is not revoked at start")
	vaultCtx, leave := context.WithCancel(ctx)
	rev.onLeave(leave)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ev.client.Run(vaultCtx)
	}()
	t.Cleanup(func() {
		leave()
		<-done
	})
	require.Eventually(t, ev.client.Connected, 5*time.Second, 5*time.Millisecond)
	late.c.Store(ev.client)
	e := &relayEnv{d: d, server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...), v: v, keys: keys}

	hold := func(from, to int) map[string]any {
		t.Helper()
		run, isError := e.call(t, "run_start", map[string]any{"intent": "Close the stale leads"})
		require.False(t, isError, "%v", run)
		held, isError := e.call(t, "write", map[string]any{
			"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", from, to},
			"intent": "They went cold", "runId": run["runId"],
		})
		require.True(t, isError)
		require.Equal(t, "APPROVAL_REQUIRED", held["code"], "%v", held)
		return held["approval"].(map[string]any)
	}

	// A held write's portal short link, and a page session on it.
	ap := hold(21, 35)
	id, secret := portalLink(t, ap["approvalUrl"].(string), "approvals")
	linkKeys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	wctx := waitCtx(t)
	page, err := pagetest.Open(wctx, v.URL(), linkKeys)
	require.NoError(t, err)
	t.Cleanup(page.Close)
	r, err := page.Do(wctx, http.MethodGet, "/api/v1/approvals/"+id, pagetest.Headers(secret), "", 0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.Status, r.Body)

	// The person revokes the engine; the next heartbeat reads it.
	_, err = guard.RevokeEngine(ctx, d.Admin, keys.EngineID())
	require.NoError(t, err)
	require.True(t, rev.check(ctx, "bot"))

	require.Equal(t, websocket.StatusCode(channel.ErrEngineRevoked), page.Closed(wctx), "the open session closes with ENGINE_REVOKED")
	require.Eventually(t, func() bool { return closes.has(websocket.StatusCode(channel.ErrEngineRevoked)) }, 5*time.Second, 5*time.Millisecond)
	_, err = pagetest.Open(wctx, v.URL(), linkKeys)
	require.Error(t, err, "the link opens no new session")

	// The agent's next held write carries the long link.
	next := hold(36, 50)
	link := next["approvalUrl"].(string)
	require.Empty(t, links.SecretOf(link), "no short link: %s", link)
	require.True(t, strings.Contains(link, "#"), link)

	// The engine serves no other database: it leaves the Vault.
	require.Eventually(t, func() bool { return !v.Connected(keys.EngineID()) }, 5*time.Second, 10*time.Millisecond)
}
