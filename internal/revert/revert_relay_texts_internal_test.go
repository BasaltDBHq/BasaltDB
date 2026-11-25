package revert

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// relayStore serves one pending revert, and a rescope that returns the
// texts it is given: the texts a store could hand the engine.
type relayStore struct {
	Store
	r        action.Revert
	rescoped action.RescopedRevert
}

func (s relayStore) FindRevert(context.Context, uuid.UUID) (action.Revert, error) { return s.r, nil }

func (relayStore) RevertNonce(context.Context, uuid.UUID) ([]byte, error) {
	return []byte("rescope nonce"), nil
}

func (relayStore) RevealNonce(context.Context, string, uuid.UUID) ([]byte, error) {
	return []byte("reveal nonce"), nil
}

func (s relayStore) RescopeRevert(context.Context, action.RescopeRequest, time.Duration) (action.RescopedRevert, error) {
	return s.rescoped, nil
}

// relayTexts are a revert's binding and lines that follow the text rules,
// and the same binding with one separator out of them.
func relayTexts(t *testing.T) (binding, broken string, lines []string) {
	t.Helper()
	lines = []string{changedAfterLine}
	binding = revertOf(t, "Undo", lines, false).BindingText
	broken = strings.Replace(binding, `"rows": 1, `, `"rows":1, `, 1)
	require.NotEqual(t, binding, broken)
	return binding, broken, lines
}

func pendingRevert(binding string, lines []string) action.Revert {
	r := caseRevert(false)
	r.Rows, r.BindingText, r.Lines, r.ExpiresAt = len(lines), binding, lines, time.Now().Add(time.Hour)
	return r
}

// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): the revert page's request refuses a binding or a
// line from the store that breaks them, served from the store or from the
// engine's memory of a widened revert.
func TestRevertRequestRefusesTextsOutOfTheRules(t *testing.T) {
	t.Parallel()
	binding, broken, lines := relayTexts(t)
	brokenLine := strings.Replace(lines[0], `"cascaded": false`, `"cascaded":false`, 1)
	const secret = "link secret"

	for name, r := range map[string]action.Revert{
		"binding": pendingRevert(broken, lines),
		"line":    pendingRevert(binding, []string{brokenLine}),
	} {
		t.Run("from the store/"+name, func(t *testing.T) {
			t.Parallel()
			rc := newService(t, "linux", "", withStore(relayStore{r: r}))
			_, err := rc.RevertRequest(context.Background(), r.ID, secret)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
		})
	}

	ok := pendingRevert(binding, lines)
	rc := newService(t, "linux", "", withStore(relayStore{r: ok}))
	_, err := rc.RevertRequest(context.Background(), ok.ID, secret)
	require.NoError(t, err, "texts in the rules are relayed")

	for name, req := range map[string]revert.Request{
		"binding": {RevertID: ok.ID, Binding: broken, Lines: lines},
		"line":    {RevertID: ok.ID, Binding: binding, Lines: []string{brokenLine}},
	} {
		t.Run("widened/"+name, func(t *testing.T) {
			t.Parallel()
			widened := ok
			widened.Widened, widened.BindingText, widened.Lines = true, "", nil
			rc := newService(t, "linux", "", withStore(relayStore{r: widened}))
			rc.rescopes.put(ok.ID, rescoped{link: sha256.Sum256([]byte(secret)), request: req, expires: time.Now().Add(time.Hour)})
			_, err := rc.RevertRequest(context.Background(), ok.ID, secret)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
		})
	}
}

// The scope route hands the page the store's rebuilt texts, which the
// person then signs: a binding or a line that breaks the text rules is
// refused before the engine keeps or relays it.
func TestRescopeRefusesTextsOutOfTheRules(t *testing.T) {
	t.Parallel()
	binding, broken, lines := relayTexts(t)
	brokenLine := strings.Replace(lines[0], `"cascaded": false`, `"cascaded":false`, 1)
	r := pendingRevert(binding, lines)
	sel := revert.Select{Scope: revert.ScopeRun, ScopeID: r.ScopeID, Agents: []string{"agent:bot"}}

	for name, out := range map[string]action.RescopedRevert{
		"binding": {RevertID: r.ID, BindingText: broken, Lines: lines, ExpiresAt: r.ExpiresAt},
		"line":    {RevertID: r.ID, BindingText: binding, Lines: []string{brokenLine}, ExpiresAt: r.ExpiresAt},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rc := newService(t, "linux", "", withStore(relayStore{r: r, rescoped: out}))
			_, err := rc.RescopeRevert(context.Background(), r.ID, "link secret", ScopeRequest{Select: sel})
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
			_, held := rc.rescopes.get(r.ID, "link secret", time.Now())
			require.False(t, held, "nothing kept for the page")
		})
	}
}
