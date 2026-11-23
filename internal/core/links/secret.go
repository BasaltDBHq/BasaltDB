package links

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// Link secrets (CONTRACT.md, Link secrets; owner decisions, Decided Nov
// 12): every short link the engine issues carries a random secret in its
// fragment, <link>#s=<secret>. The engine keeps only the secret's hash per
// held item, until the item expires.
const (
	// SecretBytes is the secret's size: 128 bits.
	SecretBytes = 16
	// SecretHeader carries the secret from the page to the engine's API.
	SecretHeader = "basalt-link-secret" //nolint:gosec // G101: a header name, not a credential
	// secretFragment starts a short link's fragment.
	SecretFragment = "s="
)

// WithSecret is the short link with its secret: <link>#s=<secret>.
func WithSecret(link, secret string) string {
	return link + "#" + SecretFragment + secret
}

// Secrets holds the hash of each held item's one live link secret, and for
// a portal short link over the Vault (a relay link; CONTRACT.md, Vault
// channel, Link secrets in a session) the linkToken and psk derived from it.
type Secrets struct {
	now  func() time.Time
	rand io.Reader
	// persist is where the hashes persist (nil keeps them in memory).
	persist Persister
	mu      sync.Mutex
	live    map[uuid.UUID]secretEntry
	// resets are the hashes of revert links an agent's reset revoked, kept
	// until the revert expires so the page can tell the person
	// (CONTRACT.md, Link secrets, LINK_RESET).
	resets map[uuid.UUID][]secretEntry
	// onDrop is told the token of every relay link that stops being live:
	// replaced, revoked or expired. It runs without mu held.
	onDrop func(channel.LinkToken)
}

type secretEntry struct {
	hash    [sha256.Size]byte
	expires time.Time
	// keys are a relay link's Vault token and psk; nil for a link to the
	// engine's local pages.
	keys *channel.LinkKeys
}

// LogValue logs a relay link by its item and expiry, never its token.
func (l RelayLink) LogValue() slog.Value {
	return slog.GroupValue(slog.String("item", l.Item.String()), slog.Time("expiresAt", l.ExpiresAt))
}

// RelayLink is a live relay link: its token and expiry.
type RelayLink struct {
	Token channel.LinkToken
	// Item is the approval or revert the link opens; logs name a link by
	// it, never by its token (a bearer handle at the Vault).
	Item      uuid.UUID
	ExpiresAt time.Time
}

// NewSecrets returns an empty store; rand is the randomness source
// (crypto/rand outside tests).
func NewSecrets(now func() time.Time, rand io.Reader) *Secrets {
	if now == nil || rand == nil {
		panic("links.NewSecrets: clock and randomness required")
	}
	return &Secrets{now: now, rand: rand, live: map[uuid.UUID]secretEntry{}, resets: map[uuid.UUID][]secretEntry{}}
}

// Persister keeps a store's encoded hashes (statefile/secretfile: the file
// <stateDir>/<agent>.links.json; CONTRACT.md, Link secrets).
type Persister interface {
	// Save replaces what is kept with raw.
	Save(raw []byte) error
}

// RestoreSecrets returns the store encoded in raw, loading its unexpired
// hashes, so short links survive an engine restart; it persists to p. Raw
// that cannot be read gives an error and an empty store that replaces it on
// the next issue.
func RestoreSecrets(raw []byte, p Persister, now func() time.Time, rand io.Reader) (*Secrets, error) {
	s := NewSecretsWith(p, now, rand)
	var file secretsFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return s, err
	}
	for _, e := range file.Links {
		entry, err := e.entry()
		if err != nil {
			return NewSecretsWith(p, now, rand), err
		}
		s.live[e.ID] = entry
	}
	for _, e := range file.Resets {
		entry, err := e.entry()
		if err != nil || entry.keys != nil {
			return NewSecretsWith(p, now, rand), errors.New("a bad reset link")
		}
		s.resets[e.ID] = append(s.resets[e.ID], entry)
	}
	// Expired relay links of a stopped engine are not unregistered: the
	// Vault drops each token at its expiresAt by itself.
	s.prune()
	return s, nil
}

// NewSecretsWith is an empty store that persists to p.
func NewSecretsWith(p Persister, now func() time.Time, rand io.Reader) *Secrets {
	s := NewSecrets(now, rand)
	s.persist = p
	return s
}

// secretsFile is the persisted store: hashes, and a relay link's token and
// psk, never a secret.
type secretsFile struct {
	Links []secretFileEntry `json:"links"`
	// Resets are revert links revoked by a reset: hash and expiry only.
	Resets []secretFileEntry `json:"resets,omitempty"`
}

type secretFileEntry struct {
	ID        uuid.UUID `json:"id"`
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkToken and PSK are a relay link's, base64url (CONTRACT.md, Vault
	// channel: the engine keeps them next to sha256(secret)).
	LinkToken string `json:"linkToken,omitempty"`
	PSK       string `json:"psk,omitempty"`
}

// entry reads one persisted link: its hash, and a relay link's token and
// psk, both or neither.
func (e secretFileEntry) entry() (secretEntry, error) {
	hash, err := hex.DecodeString(e.Hash)
	if err != nil || len(hash) != sha256.Size {
		return secretEntry{}, errors.New("a bad hash")
	}
	out := secretEntry{hash: [sha256.Size]byte(hash), expires: e.ExpiresAt}
	if e.LinkToken == "" && e.PSK == "" {
		return out, nil
	}
	token, err := channel.ParseLinkToken(e.LinkToken)
	if err != nil {
		return secretEntry{}, errors.New("a bad link token")
	}
	psk, err := base64.RawURLEncoding.Strict().DecodeString(e.PSK)
	if err != nil || len(psk) != channel.PSKLen {
		return secretEntry{}, errors.New("a bad psk")
	}
	out.keys = &channel.LinkKeys{Token: token, PSK: channel.PSK(psk)}
	clear(psk)
	return out, nil
}

// save hands the encoded store to its Persister; the caller holds mu. A
// store without one keeps its hashes in memory.
func (s *Secrets) save() error {
	if s.persist == nil {
		return nil
	}
	file := secretsFile{Links: make([]secretFileEntry, 0, len(s.live))}
	for id, e := range s.live {
		entry := secretFileEntry{ID: id, Hash: hex.EncodeToString(e.hash[:]), ExpiresAt: e.expires}
		if e.keys != nil {
			entry.LinkToken = e.keys.Token.Wire()
			entry.PSK = base64.RawURLEncoding.EncodeToString(e.keys.PSK[:])
		}
		file.Links = append(file.Links, entry)
	}
	for id, list := range s.resets {
		for _, e := range list {
			file.Resets = append(file.Resets, secretFileEntry{ID: id, Hash: hex.EncodeToString(e.hash[:]), ExpiresAt: e.expires})
		}
	}
	raw, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return s.persist.Save(raw)
}

// OnDrop sets what is told the token of every relay link that stops being
// live (replaced by a newer link, revoked or expired), so the engine
// unregisters it at the Vault. It is set once, before the store is used.
func (s *Secrets) OnDrop(f func(channel.LinkToken)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDrop = f
}

// Issue makes a new secret for item id, valid until expires, and revokes
// the item's earlier one.
func (s *Secrets) Issue(id uuid.UUID, expires time.Time) (string, error) {
	secret, _, err := s.issue(id, expires, false)
	return secret, err
}

// IssueRelay makes a new secret for item id, valid until expires, for a
// portal short link over the Vault, and revokes the item's earlier one. It
// keeps the linkToken and psk derived from the secret and returns the
// token: of the three, the only one the Vault may see.
func (s *Secrets) IssueRelay(id uuid.UUID, expires time.Time) (string, channel.LinkToken, error) {
	return s.issue(id, expires, true)
}

func (s *Secrets) issue(id uuid.UUID, expires time.Time, relay bool) (string, channel.LinkToken, error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", channel.LinkToken{}, fmt.Errorf("link secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	entry := secretEntry{hash: sha256.Sum256([]byte(secret)), expires: expires}
	var token channel.LinkToken
	if relay {
		keys, err := channel.DeriveLink(secret)
		if err != nil {
			return "", channel.LinkToken{}, err
		}
		entry.keys, token = &keys, keys.Token
	}
	s.mu.Lock()
	dropped := s.prune()
	if old, ok := s.live[id]; ok && old.keys != nil {
		dropped = append(dropped, old.keys.Token)
	}
	s.live[id] = entry
	err := s.save()
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	if err != nil {
		return "", channel.LinkToken{}, err
	}
	return secret, token, nil
}

// Revoke revokes item id's link when it is still the relay link of token
// (a newer link is left alone), as when the Vault did not register it.
func (s *Secrets) Revoke(id uuid.UUID, token channel.LinkToken) error {
	return s.revokeWhere(func(eid uuid.UUID, e secretEntry) bool {
		return eid == id && e.keys != nil && e.keys.Token == token
	}, true)
}

// RevokeItem revokes item id's live link, whatever it is, as when the
// person rejected the revert: the page holding it then reads an unknown
// id, and a relay link's sessions end.
func (s *Secrets) RevokeItem(id uuid.UUID) error {
	return s.revokeWhere(func(eid uuid.UUID, _ secretEntry) bool { return eid == id }, true)
}

// RevokeToken revokes the relay link of token, whichever item holds it, as
// when another engine registered that token (VC-42). It reports whether
// this store held it. It tells onDrop nothing: the Vault said the token is
// another engine's, so unregistering it is pointless, and the caller may be
// the socket's read loop, which must not write.
func (s *Secrets) RevokeToken(token channel.LinkToken) (bool, error) {
	held := false
	err := s.revokeWhere(func(_ uuid.UUID, e secretEntry) bool {
		match := e.keys != nil && e.keys.Token == token
		held = held || match
		return match
	}, false)
	return held, err
}

// RevokeRelay revokes every relay link.
func (s *Secrets) RevokeRelay() error {
	return s.revokeWhere(func(_ uuid.UUID, e secretEntry) bool { return e.keys != nil }, true)
}

// revokeWhere deletes the entries match picks and saves the store. With
// tellDrop it also prunes expired links and tells onDrop every dropped
// token; without, it calls onDrop for nothing (expired links wait for the
// next prune).
func (s *Secrets) revokeWhere(match func(uuid.UUID, secretEntry) bool, tellDrop bool) error {
	s.mu.Lock()
	var dropped []channel.LinkToken
	if tellDrop {
		dropped = s.prune()
	}
	removed := false
	for id, e := range s.live {
		if !match(id, e) {
			continue
		}
		delete(s.live, id)
		removed = true
		if tellDrop && e.keys != nil {
			dropped = append(dropped, e.keys.Token)
		}
	}
	var err error
	if removed {
		err = s.save()
	}
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return err
}

// Relay lists the live relay links, which the engine registers with the
// Vault again after every READY.
func (s *Secrets) Relay() []RelayLink {
	s.mu.Lock()
	dropped := s.prune()
	out := make([]RelayLink, 0, len(s.live))
	for id, e := range s.live {
		if e.keys != nil {
			out = append(out, RelayLink{Token: e.keys.Token, Item: id, ExpiresAt: e.expires})
		}
	}
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return out
}

// SessionLink is the live relay link a session's token names.
type SessionLink struct {
	Item      uuid.UUID
	Keys      channel.LinkKeys
	ExpiresAt time.Time
}

// LogValue logs the item and the expiry only, never the link's keys.
// String names the item and the expiry, never the link's keys.
func (l SessionLink) String() string {
	return "session link for " + l.Item.String() + " until " + l.ExpiresAt.UTC().Format(time.RFC3339)
}

// GoString is String: %#v would print the token and the key's fields.
func (l SessionLink) GoString() string { return l.String() }

// LogValue is the item and the expiry, as String.
func (l SessionLink) LogValue() slog.Value {
	return slog.GroupValue(slog.String("item", l.Item.String()), slog.Time("expiresAt", l.ExpiresAt))
}

// Session finds the live, unexpired relay link of token (CONTRACT.md,
// Vault channel: message 1 names its link by token). It compares every
// relay link's token in constant time and does the same work whether it
// finds one or not. It drops nothing and tells onDrop nothing: it runs on
// the Vault socket's read loop, which must not write.
func (s *Secrets) Session(token channel.LinkToken) (SessionLink, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out SessionLink
	found := 0
	for id, e := range s.live {
		if e.keys == nil {
			continue
		}
		match := subtle.ConstantTimeCompare(e.keys.Token[:], token[:]) & boolInt(now.Before(e.expires))
		if match == 1 {
			out = SessionLink{Item: id, Keys: *e.keys, ExpiresAt: e.expires}
		}
		found |= match
	}
	return out, found == 1
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Prune drops expired links now, telling onDrop the relay links' tokens.
// The engine calls it on a timer, so an expired link is unregistered at the
// Vault even when nothing else touches the store.
func (s *Secrets) Prune() {
	s.mu.Lock()
	dropped := s.prune()
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
}

// Check reports whether secret is item id's live, unexpired secret. It
// compares in constant time, and does the same work for an unknown id.
func (s *Secrets) Check(id uuid.UUID, secret string) bool {
	got := sha256.Sum256([]byte(secret))
	s.mu.Lock()
	dropped := s.prune()
	e, ok := s.live[id]
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	match := subtle.ConstantTimeCompare(got[:], e.hash[:]) == 1
	return ok && secret != "" && match
}

// HasRelay reports whether item id has a live, unexpired portal short link
// (one issued with IssueRelay): the person holds a link the relay carries,
// so a result that issues no new link points back to it.
func (s *Secrets) HasRelay(id uuid.UUID) bool {
	s.mu.Lock()
	dropped := s.prune()
	e, ok := s.live[id]
	f := s.onDrop
	s.mu.Unlock()
	tell(f, dropped)
	return ok && e.keys != nil
}

// prune drops expired secrets and returns the relay links' tokens among
// them; the caller holds mu.
func (s *Secrets) prune() []channel.LinkToken {
	now := s.now()
	var dropped []channel.LinkToken
	for id, e := range s.live {
		if now.Before(e.expires) {
			continue
		}
		delete(s.live, id)
		if e.keys != nil {
			dropped = append(dropped, e.keys.Token)
		}
	}
	for id, list := range s.resets {
		kept := list[:0]
		for _, e := range list {
			if now.Before(e.expires) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(s.resets, id)
			continue
		}
		s.resets[id] = kept
	}
	return dropped
}

// tell hands dropped tokens to onDrop, when it is set.
func tell(f func(channel.LinkToken), dropped []channel.LinkToken) {
	if f == nil {
		return
	}
	for _, t := range dropped {
		f(t)
	}
}
