package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// HeldNotice is a held write to tell the person about.
type HeldNotice struct {
	ApprovalID uuid.UUID
	Agent      string
	Intent     string
	Statement  string
	Rows       int
	// Headline states what the write changes, cascades explicit
	// (approval.Summary.Headline).
	Headline    string
	ExpiresAt   time.Time
	ApprovalURL string
	// ShortURL is the short link with its secret, when the engine serves
	// the pages; it works on the engine's machine only.
	ShortURL string
}

// RevertNotice is a revert waiting for the person's signature, to tell
// them about when the agent requests it or has its link issued again
// (owner decision LP-2).
type RevertNotice struct {
	RevertID uuid.UUID
	Agent    string
	// Headline is built from what Postgres returned (revertHeadline).
	Headline  string
	Intent    string
	ExpiresAt time.Time
	// RevertURL is the long link, ShortURL the short one when the engine
	// serves the pages. Both are empty for a widened revert, whose notice
	// carries only the headline (LP-3).
	RevertURL string
	ShortURL  string
	Widened   bool
}

// Notifier tells the person a write is held or a revert waits for them.
// The engine has no notifier today, so it is noNotifier; it is the seam a
// notification channel plugs into later. It only delivers the link;
// approving and signing need the person's passkey.
type Notifier interface {
	NotifyHeld(ctx context.Context, n HeldNotice) error
	NotifyRevert(ctx context.Context, n RevertNotice) error
}

// noNotifier is the Notifier when none is configured.
type noNotifier struct{}

func (noNotifier) NotifyHeld(context.Context, HeldNotice) error { return nil }

func (noNotifier) NotifyRevert(context.Context, RevertNotice) error { return nil }

// heldNotice is a held write as the agent hands it to the person
// (CONTRACT.md, Handing a held action to the person), with the long link
// for notifications.
type heldNotice struct {
	toolresult.ApprovalNotice
	// pick is the link handed over, as chooseLink chose it (the long link
	// when a wait or a list only restates it while the engine serves the pages).
	pick     handOver
	longURL  string
	shortURL string // "" when no short link was issued
	// shortHeld is set when the person holds a short link to the item that
	// still works (shortLinked): a restating result points back to it.
	shortHeld bool
	// reason is the APPROVAL_REQUIRED case: HELD, HELD_NO_PAGES, NO_PASSKEY
	// or REQUEST_TOO_LARGE (WAIT_ENDED is set by the wait that ran out).
	reason string
	// steps are the next steps of a REQUEST_TOO_LARGE notice, built where
	// the run is known; nil otherwise.
	steps []toolresult.NextStep
}

// Whether building a notice issues a new short link, revoking the item's
// earlier one (CONTRACT.md, Link secrets).
const (
	issueLink = true
	keepLink  = false
)

// shortLink issues a new short link page(origin, id)#s=<secret> for an
// item that expires at expires, revoking its earlier one, when issue is
// set: the portal's short link when the Vault registered it (relayLink),
// else one to the pages this engine
// serves; else "", and the caller hands over the long link.
func (dc *deliveryCase) shortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error) {
	if !issue {
		return "", nil
	}
	if link := dc.relayLink(ctx, page, id, expires); link != "" {
		return link, nil
	}
	return dc.localLink(page, id, expires)
}

// localLink issues a new short link to the pages this engine serves,
// revoking the item's earlier link; "" when it serves none.
func (dc *deliveryCase) localLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error) {
	if dc.core.PagesOrigin == "" {
		return "", nil
	}
	secret, err := dc.deps.Links.Issue(id, expires)
	if err != nil {
		return "", err
	}
	return links.WithSecret(page(dc.core.PagesOrigin, id), secret), nil
}

// credentialIDs are the registered passkeys that can sign on the pages the
// agent's links open (pagesPasskeys), for the request's allowCredentials:
// none is a request nobody can sign yet.
func (dc *deliveryCase) credentialIDs(ctx context.Context) ([]passkey.Bytes, error) {
	all, err := dc.approvals.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	keys, _ := passkey.OnPagesOrigin(all, dc.core.PagesBase)
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids, nil
}

// awaitWhile polls while pending reports true: every dc.deps.Poll it calls
// refresh, until pending is false, the wait is over by dc.core.Now, or ctx ends
// (then ctx's error). It holds no transaction between reads. The waiting
// write and request_revert's wait share it.
func (dc *deliveryCase) awaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error {
	deadline := dc.core.Now().Add(wait)
	tick := time.NewTicker(dc.deps.Poll)
	defer tick.Stop()
	for pending() && dc.core.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		if err := refresh(ctx); err != nil {
			return err
		}
	}
	return nil
}
