package vault

import (
	corelinks "github.com/basaltdbhq/basaltdb/internal/core/links"
)

// LinksOf is the engine's live relay links as the client registers them.
func LinksOf(live []corelinks.RelayLink) []Link {
	out := make([]Link, 0, len(live))
	for _, l := range live {
		out = append(out, Link{Token: l.Token, Item: l.Item, ExpiresAt: l.ExpiresAt})
	}
	return out
}

// SessionOf is the relay link l that agent's store holds, as a session
// reads it, when found. It zeroes l's psk once copied: the session's copy
// is the one left, and its caller zeroes it once the tag is checked.
func SessionOf(agent string, l corelinks.SessionLink, found bool) (SessionLink, bool) {
	defer l.Keys.PSK.Zero()
	if !found {
		return SessionLink{}, false
	}
	return SessionLink{Token: l.Keys.Token, Agent: agent, Item: l.Item, PSK: l.Keys.PSK, ExpiresAt: l.ExpiresAt}, true
}
