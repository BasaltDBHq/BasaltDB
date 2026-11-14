package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

// directRecordTimeout bounds the read of the engine's record before a link
// is handed over; a slower database gets the long link.
const directRecordTimeout = 2 * time.Second

// directLink is a new portal short link for the DIRECT transport, or "" to
// fall back (CONTRACT.md, Direct transport, Which transport, and which
// link). Only when the agent is direct-ready: the engine issues the link's
// secret and keeps the token and psk derived from it, which its direct
// listener looks the session up by. Nothing is registered anywhere and
// nothing goes to the Vault: the portal page reaches the engine through the
// person's own tunnel, at the address this device pinned. The link is the
// same as a relay's, with no engine address and no transport hint.
func (s *Service) directLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) string {
	if !s.directReady(ctx) {
		return ""
	}
	secret, _, err := s.Links.IssueRelay(id, expires)
	if err != nil {
		s.Log.Error("issue a portal short link for the direct transport; handing over the long link", "id", id, "err", err)
		return ""
	}
	return links.WithSecret(page(s.PagesBase, id), secret)
}

// directReady reports whether the agent is direct-ready: the engine has a
// direct listener (directAddr is not off), its pages are the portal's, and
// the agent's database records this engine's key, not revoked, with an
// address. A record that cannot be read (an older guard, a slow or
// unreachable database, the key file refused) is not ready.
func (s *Service) directReady(ctx context.Context) bool {
	if !s.DirectServed || s.EngineRecord == nil || s.Vault == nil || s.PagesBase != links.Portal {
		return false
	}
	engineID := s.Vault.VaultStatus().EngineID
	if engineID == "" {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, directRecordTimeout)
	defer cancel()
	e, err := s.EngineRecord(rctx, engineID)
	if err != nil {
		s.Log.Warn("read the engine's record for a direct link; handing over the long link", "err", err)
		return false
	}
	return e != nil && e.RevokedAt == nil && e.URL != nil && *e.URL != ""
}
