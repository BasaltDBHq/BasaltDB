package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// Portal short links on the tunnel path with the Vault off (CONTRACT.md,
// Direct transport, Which transport, and which link): the engine hands over
// the portal short link when the agent is direct-ready, keeps its token and
// psk for the direct listener, and contacts no relay.

const directEngineID = "R68WFYxAcGgIjMENS5Oqrw"

// offVault is the Vault reporter of an engine with the Vault off whose key
// file loads.
type offVault struct{ id string }

func (v offVault) VaultStatus() VaultStatus { return VaultStatus{State: "OFF", EngineID: v.id} }

// countingRelay fails the test's promise that nothing contacts a relay: it
// counts every call.
type countingRelay struct{ calls atomic.Int32 }

func (r *countingRelay) Connected() bool {
	r.calls.Add(1)
	return false
}

func (r *countingRelay) Register(context.Context, channel.LinkToken, time.Time) error {
	r.calls.Add(1)
	return errors.New("no relay")
}

func engineRow(url string, revoked bool) *guard.RecordedEngine {
	e := &guard.RecordedEngine{ID: directEngineID, RecordedAt: time.Now()}
	if url != "" {
		e.URL = &url
	}
	if revoked {
		at := time.Now()
		e.RevokedAt = &at
	}
	return e
}

type directEnv struct {
	svc   *Service
	reads atomic.Int32
	ids   []string
}

// newDirectEnv is an agent service on a portal engine with the Vault off,
// tune changing its deps; record answers the engine record read.
func newDirectEnv(t *testing.T, record func() (*guard.RecordedEngine, error), tune func(*Deps)) *directEnv {
	t.Helper()
	e := &directEnv{}
	d := deps()
	d.Approvals = catalogApprovals{}
	d.Reverts = catalogReverts{}
	d.PagesBase = links.Portal
	d.Links = links.NewSecrets(time.Now, rand.Reader)
	d.Vault = offVault{id: directEngineID}
	d.DirectServed = true
	d.EngineRecord = func(_ context.Context, id string) (*guard.RecordedEngine, error) {
		e.reads.Add(1)
		e.ids = append(e.ids, id)
		return record()
	}
	if tune != nil {
		tune(&d)
	}
	e.svc = NewService(d)
	return e
}

func (e *directEnv) notice(t *testing.T) heldNotice {
	t.Helper()
	n, err := e.svc.approvalNotice(context.Background(), uuid.MustParse(caseApproval), noticeBinding, bigLines(3), time.Now().Add(time.Hour), issueLink)
	require.NoError(t, err)
	requirePersonMessage(t, n.PersonMessage, n.Links)
	return n
}

func TestDirectReadyHandsOverThePortalShortLinkWithTheVaultOff(t *testing.T) {
	t.Parallel()
	relay := &countingRelay{}
	e := newDirectEnv(t, func() (*guard.RecordedEngine, error) { return engineRow("https://engine.example.com", false), nil },
		func(d *Deps) { d.Relay = relay })
	n := e.notice(t)

	require.True(t, strings.HasPrefix(n.ApprovalURL, links.Portal+"/approvals/"+caseApproval+"#s="), n.ApprovalURL)
	require.Equal(t, n.ApprovalURL, n.shortURL)
	require.NotContains(t, n.ApprovalURL, "engine.example.com", "a link never carries the engine address")
	require.Contains(t, n.PersonMessage, "\n\n"+n.ApprovalURL+"\n\n")
	require.Equal(t, []string{directEngineID}, e.ids, "the record of this engine's own key")

	// The direct listener finds the session by the link's token.
	secret := links.SecretOf(n.ApprovalURL)
	keys, err := channel.DeriveLink(secret)
	require.NoError(t, err)
	live := e.svc.Links.Relay()
	require.Len(t, live, 1)
	require.Equal(t, keys.Token, live[0].Token)
	require.True(t, e.svc.Links.Check(uuid.MustParse(caseApproval), secret))

	// Only Connected was asked (false: the Vault is off); nothing was registered.
	require.Equal(t, int32(1), relay.calls.Load())

	// A revert's link goes the same way.
	id := uuid.Must(uuid.NewV7())
	link, err := e.svc.shortLink(context.Background(), links.Revert, id, time.Now().Add(time.Hour), issueLink)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(link, links.Portal+"/reverts/"+id.String()+"#s="), link)
}

func TestNotDirectReadyHandsOverTheLongLink(t *testing.T) {
	t.Parallel()
	ok := func() (*guard.RecordedEngine, error) { return engineRow("https://engine.example.com", false), nil }
	cases := map[string]struct {
		record func() (*guard.RecordedEngine, error)
		tune   func(*Deps)
	}{
		"no direct listener":          {ok, func(d *Deps) { d.DirectServed = false }},
		"not recorded":                {func() (*guard.RecordedEngine, error) { return nil, nil }, nil}, //nolint:nilnil // not recorded is (nil, nil), as guard.EngineRecord answers
		"revoked":                     {func() (*guard.RecordedEngine, error) { return engineRow("https://engine.example.com", true), nil }, nil},
		"no address":                  {func() (*guard.RecordedEngine, error) { return engineRow("", false), nil }, nil},
		"record unreadable":           {func() (*guard.RecordedEngine, error) { return nil, errors.New("relation does not exist") }, nil},
		"key file refused":            {ok, func(d *Deps) { d.Vault = offVault{} }},
		"no vault reporter":           {ok, func(d *Deps) { d.Vault = nil }},
		"no record reader":            {ok, func(d *Deps) { d.EngineRecord = nil }},
		"local pages, not the portal": {ok, func(d *Deps) { d.PagesBase = links.DefaultLocal }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newDirectEnv(t, c.record, c.tune)
			n := e.notice(t)
			require.Empty(t, n.shortURL)
			require.Equal(t, n.longURL, n.ApprovalURL)
			require.Empty(t, e.svc.Links.Relay(), "no secret is issued")
		})
	}
}

// A wait or a list that issues no link reads nothing.
func TestDirectLinkOnlyWhenALinkIsIssued(t *testing.T) {
	t.Parallel()
	e := newDirectEnv(t, func() (*guard.RecordedEngine, error) { return engineRow("https://engine.example.com", false), nil }, nil)
	link, err := e.svc.shortLink(context.Background(), links.Approval, uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour), false)
	require.NoError(t, err)
	require.Empty(t, link)
	require.Zero(t, e.reads.Load())
}
