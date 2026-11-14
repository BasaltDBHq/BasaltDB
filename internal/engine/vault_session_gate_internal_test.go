package engine

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/vault/pagetest"
)

// unsafeGuard is a guard this build does not serve: it misses a breaking
// migration, so Service.Admit refuses every page call.
type unsafeGuard struct{}

func (unsafeGuard) GuardStatus(context.Context) (guard.Status, error) {
	v := guard.LatestVersion()
	return guard.Status{State: guard.GuardOutdated, Installed: v - 1, Build: v, MissingBreaking: []int{v}}, nil
}

func (unsafeGuard) SetupRecorded(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (unsafeGuard) LatestSetup(context.Context) (guard.AgentSetup, bool, error) {
	return guard.AgentSetup{}, false, nil
}

func (unsafeGuard) LedgerBytes(context.Context) (int64, error) { return 0, nil }

func (unsafeGuard) Reinstalls(context.Context) (guard.Reinstalls, error) {
	return guard.Reinstalls{}, nil
}

// gatedService is a real agent service on an unsafe guard. Its stores are
// empty interfaces: a call that got past Admit would panic, so a test that
// passes relayed nothing.
func gatedService(store *links.Secrets) *agent.Service {
	return agent.NewService(agent.Deps{
		Name: "demo_bot", Reader: struct{ agent.Reader }{}, Store: struct{ agent.Store }{},
		Reads: struct{ agent.ReadRecorder }{}, Approvals: struct{ agent.ApprovalStore }{},
		Reverts: struct{ agent.RevertStore }{}, Log: quietLog(), Now: time.Now,
		PagesBase: links.Portal, Links: store, Probe: unsafeGuard{},
	})
}

// On a guard the engine calls unsafe, a session's reads and relays get the
// same answer as on loopback, and nothing is relayed: the session reaches
// the agent service through the same gate (Service.Admit) as the loopback
// listener.
func TestVaultSessionOnAnUnsafeGuardAnswersAsLoopback(t *testing.T) {
	t.Parallel()
	store := links.NewSecrets(time.Now, rand.Reader)
	svc := gatedService(store)
	id := uuid.Must(uuid.NewV7())
	s := serveOverVault(t, &wire{}, svc, store, id)

	loopback := pages.New(links.Portal, quietLog())
	loopback.Add(svc)
	h := loopback.Handler()
	viaLoopback := func(method, path string, headers map[string]string, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	as, err := person.Sign(approval.Challenge("{}"), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	approveBody, err := json.Marshal(approval.NewResponse(id, as))
	require.NoError(t, err)
	applyBody, err := json.Marshal(revert.NewResponse(id, as))
	require.NoError(t, err)

	p := s.open(t)
	ctx := waitCtx(t)
	cases := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/v1/approvals/" + id.String(), ""},
		{http.MethodPost, "/api/v1/approvals/" + id.String() + "/approve", string(approveBody)},
		{http.MethodGet, "/api/v1/reverts/" + id.String(), ""},
		{http.MethodPost, "/api/v1/reverts/" + id.String() + "/apply", string(applyBody)},
		{http.MethodPost, "/api/v1/reverts/" + id.String() + "/scope", `{"select":{"scope":"TASK","scopeId":"` + id.String() + `"}}`},
	}
	for _, c := range cases {
		headers := pagetest.Headers(s.secret)
		if c.method == http.MethodPost {
			headers = pagetest.PostHeaders(s.secret)
		}
		status, body := viaLoopback(c.method, c.path, headers, c.body)
		require.Equal(t, http.StatusServiceUnavailable, status, "%s %s on loopback: %s", c.method, c.path, body)
		require.Contains(t, body, `"code":"UNAVAILABLE"`)

		r, err := p.Do(ctx, c.method, c.path, headers, c.body, 0)
		require.NoError(t, err)
		require.Equal(t, status, r.Status, "%s %s", c.method, c.path)
		require.Equal(t, body, r.Body, "%s %s: the session answers as loopback", c.method, c.path)
	}
}
