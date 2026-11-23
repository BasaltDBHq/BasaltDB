package links

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// A revert's link after the person changed its scope (CONTRACT.md, Link
// secrets, A widened revert): a proven widen rotates the link to the
// secret the page made, and the agent's reset revokes the person's link
// but keeps its hash, so the page can say why it stopped working.

// ErrNoLiveLink is a rotation or extension of an item whose link is no
// longer live: revoked or expired meanwhile.
var ErrNoLiveLink = errors.New("links: the item has no live link")

// ErrBadSecret is a secret that is not SecretBytes of base64url.
var ErrBadSecret = errors.New("links: a link secret is 16 bytes of base64url")

// DecodeSecret is the raw bytes of a link secret: base64url without
// padding, exactly SecretBytes long.
func DecodeSecret(secret string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != SecretBytes {
		clear(raw)
		return nil, ErrBadSecret
	}
	return raw, nil
}

// Rotated is the link an item has after Rotate: for a relay link, its new
// Vault token and the old one, which the caller retires.
type Rotated struct {
	Relay    bool
	Token    channel.LinkToken
	OldToken channel.LinkToken
}

// LogValue logs whether the link is a relay link, never its tokens: the
// item and expiry are the caller's to log.
func (r Rotated) LogValue() slog.Value { return slog.GroupValue(slog.Bool("relay", r.Relay)) }

// String and GoString never show the tokens either.
func (r Rotated) String() string { return fmt.Sprintf("rotated link (relay %t)", r.Relay) }

// GoString is String.
func (r Rotated) GoString() string { return r.String() }

// Rotate replaces item id's live link with secret, a secret the person's
// page made, valid until expires. The old secret stops working at once. A
// relay link stays a relay link: its token and psk are derived from the
// new secret. Rotate tells onDrop nothing about the old token: the
// rotation runs inside the person's Vault session, which must stay open,
// so the caller ends the old token's other sessions itself, and the Vault
// drops the old token at its expiry.
func (s *Secrets) Rotate(id uuid.UUID, secret string, expires time.Time) (Rotated, error) {
	raw, err := DecodeSecret(secret)
	if err != nil {
		return Rotated{}, err
	}
	clear(raw)
	entry := secretEntry{hash: sha256.Sum256([]byte(secret)), expires: expires}
	s.mu.Lock()
	dropped := s.prune()
	out, err := s.rotate(id, secret, entry)
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return out, err
}

// rotate is Rotate with mu held.
func (s *Secrets) rotate(id uuid.UUID, secret string, entry secretEntry) (Rotated, error) {
	old, ok := s.live[id]
	if !ok {
		return Rotated{}, ErrNoLiveLink
	}
	var out Rotated
	if old.keys != nil {
		keys, err := channel.DeriveLink(secret)
		if err != nil {
			return Rotated{}, err
		}
		entry.keys = &keys
		out = Rotated{Relay: true, Token: keys.Token, OldToken: old.keys.Token}
	}
	s.live[id] = entry
	if err := s.save(); err != nil {
		return Rotated{}, err
	}
	return out, nil
}

// Extend moves item id's live link to expire at expires, as when a rescope
// restarts the revert's hour. It returns the relay link to register again
// with its new expiry, and false for a link to the local pages.
func (s *Secrets) Extend(id uuid.UUID, expires time.Time) (RelayLink, bool, error) {
	s.mu.Lock()
	dropped := s.prune()
	e, ok := s.live[id]
	var err error
	var out RelayLink
	relay := false
	switch {
	case !ok:
		err = ErrNoLiveLink
	default:
		e.expires = expires
		s.live[id] = e
		err = s.save()
		if e.keys != nil {
			out, relay = RelayLink{Token: e.keys.Token, ExpiresAt: expires}, true
		}
	}
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return out, relay, err
}

// Reset revokes item id's live link because the agent reset the revert to
// its own proposal, and keeps the link's hash until until, so WasReset
// can tell the page holding it. An item with no live link keeps nothing.
func (s *Secrets) Reset(id uuid.UUID, until time.Time) error {
	s.mu.Lock()
	dropped := s.prune()
	e, ok := s.live[id]
	var err error
	if ok {
		delete(s.live, id)
		if e.keys != nil {
			dropped = append(dropped, e.keys.Token)
		}
		s.resets[id] = append(s.resets[id], secretEntry{hash: e.hash, expires: until})
		err = s.save()
	}
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return err
}

// WasReset reports whether secret is a link of item id that a reset
// revoked, until the revert expires. It compares in constant time.
func (s *Secrets) WasReset(id uuid.UUID, secret string) bool {
	if secret == "" {
		return false
	}
	got := sha256.Sum256([]byte(secret))
	s.mu.Lock()
	dropped := s.prune()
	list := s.resets[id]
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	match := 0
	for _, e := range list {
		match |= subtle.ConstantTimeCompare(got[:], e.hash[:])
	}
	return match == 1
}
