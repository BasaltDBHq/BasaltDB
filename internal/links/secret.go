package links

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	secretFragment = "s="
	// proofLabel separates the issue proof from the passkey challenge,
	// sha256(binding text), which signed responses reveal.
	proofLabel = "basalt-link.1\n"
)

// WithSecret is the short link with its secret: <link>#s=<secret>.
func WithSecret(link, secret string) string {
	return link + "#" + secretFragment + secret
}

// SecretOf is the secret a short link carries, or "".
func SecretOf(link string) string {
	_, frag, ok := strings.Cut(link, "#")
	if !ok {
		return ""
	}
	secret, _ := strings.CutPrefix(frag, secretFragment)
	if secret == frag {
		return ""
	}
	return secret
}

// IssueProof is what the CLI shows to have a short link issued for an
// item: lowercase hex of sha256("basalt-link.1\n" + binding text). Only a
// holder of the binding text, who can see the whole preview already, has
// it.
func IssueProof(bindingText string) string {
	sum := sha256.Sum256([]byte(proofLabel + bindingText))
	return hex.EncodeToString(sum[:])
}

// ProofMatches compares a proof with the binding text's in constant time.
func ProofMatches(bindingText, proof string) bool {
	return subtle.ConstantTimeCompare([]byte(IssueProof(bindingText)), []byte(proof)) == 1
}

// Secrets holds the hash of each held item's one live link secret.
type Secrets struct {
	now  func() time.Time
	rand io.Reader
	mu   sync.Mutex
	live map[uuid.UUID]secretEntry
}

type secretEntry struct {
	hash    [sha256.Size]byte
	expires time.Time
}

// NewSecrets returns an empty store; rand is the randomness source
// (crypto/rand outside tests).
func NewSecrets(now func() time.Time, rand io.Reader) *Secrets {
	if now == nil || rand == nil {
		panic("links.NewSecrets: clock and randomness required")
	}
	return &Secrets{now: now, rand: rand, live: map[uuid.UUID]secretEntry{}}
}

// Issue makes a new secret for item id, valid until expires, and revokes
// the item's earlier one.
func (s *Secrets) Issue(id uuid.UUID, expires time.Time) (string, error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", fmt.Errorf("link secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.live[id] = secretEntry{hash: sha256.Sum256([]byte(secret)), expires: expires}
	return secret, nil
}

// Check reports whether secret is item id's live, unexpired secret. It
// compares in constant time, and does the same work for an unknown id.
func (s *Secrets) Check(id uuid.UUID, secret string) bool {
	got := sha256.Sum256([]byte(secret))
	s.mu.Lock()
	e, ok := s.live[id]
	if ok && !s.now().Before(e.expires) {
		delete(s.live, id)
		ok = false
	}
	s.mu.Unlock()
	match := subtle.ConstantTimeCompare(got[:], e.hash[:]) == 1
	return ok && secret != "" && match
}

// prune drops expired secrets; the caller holds mu.
func (s *Secrets) prune() {
	now := s.now()
	for id, e := range s.live {
		if !now.Before(e.expires) {
			delete(s.live, id)
		}
	}
}
