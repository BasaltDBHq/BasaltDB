package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// LinkRelay registers portal short links with the Vault (CONTRACT.md, Vault
// channel, The engine's socket to the Vault). *vault.Client is the one
// implementation outside tests.
type LinkRelay interface {
	// Connected reports whether the engine's socket is READY.
	Connected() bool
	// Register routes token to this engine until expiresAt; any error
	// means the link must not be handed over.
	Register(ctx context.Context, token channel.LinkToken, expiresAt time.Time) error
}

// RelayLink is a new portal short link over the Vault (CONTRACT.md, Vault
// channel), or "" to fall back. Only while the socket is READY: the engine
// issues the link's secret, registers the token derived from it (never the
// secret or its psk) and waits up to vault.RegisterTimeout for OK. With no
// socket, an ERROR or no answer, the new link is revoked and never handed
// over, and the caller falls back (CONTRACT.md: the short link is not
// issued). Issuing revokes the item's earlier link, whose token the link
// store's OnDrop unregisters; so does revoking this one.
func (dc *deliveryCase) RelayLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) string {
	if !dc.deps.Relay.Connected() {
		return ""
	}
	secret, token, err := dc.deps.Links.IssueRelay(id, expires)
	if err != nil {
		dc.core.Log.Error("issue a portal short link; handing over the long link", "id", id, "err", err)
		return ""
	}
	err = dc.deps.Relay.Register(ctx, token, expires)
	if err == nil {
		return links.WithSecret(page(dc.core.PagesBase, id), secret)
	}
	msg := "the Vault did not register the short link; handing over the long link"
	var rerr error
	switch {
	case dc.deps.VaultConflict(err):
		// VC-42: another engine holds this token. The link is revoked, and
		// the item's next link has a new secret whose token nobody else
		// knows. No UNREGISTER: the token is not this engine's.
		msg = "another engine registered this link's token at the Vault; the link is revoked and the long link handed over"
		_, rerr = dc.deps.Links.RevokeToken(token)
	default:
		// The registration may still land late: revoking unregisters it.
		rerr = dc.deps.Links.Revoke(id, token)
	}
	if rerr != nil {
		dc.core.Log.Error("revoke an unregistered short link", "id", id, "err", rerr)
	}
	dc.core.Log.Warn(msg, "id", id, "err", err)
	return ""
}

// ShortLinked reports whether the person holds a short link to item id that
// still works: the engine serves its own pages, or the item has a live
// portal short link the relay carries. A result that issues no new link then
// points back to that link, never to the long one.
func (dc *deliveryCase) ShortLinked(id uuid.UUID) bool {
	return dc.core.PagesOrigin != "" || (dc.deps.Links != nil && dc.deps.Links.HasRelay(id))
}

// noRelay is LinkRelay with the Vault off: never connected.
type noRelay struct{ notConnected error }

func (noRelay) Connected() bool { return false }

func (r noRelay) Register(context.Context, channel.LinkToken, time.Time) error {
	return r.notConnected
}
