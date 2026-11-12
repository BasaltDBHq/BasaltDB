package pii

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
)

// idChars is how many base32 characters of the HMAC a token keeps, for every
// entity type: 60 bits.
const idChars = 12

// redactedDomain is the domain of an email token whose provider is not common,
// so the token still looks like an email but names no organization.
const redactedDomain = "redacted.invalid"

// Token id prefixes. The pii prefix carries the key version.
const (
	personPrefix  = "Person "
	addressPrefix = "Address "
)

var (
	b32       = base32.StdEncoding.WithPadding(base32.NoPadding)
	piiPrefix = "pii" + strconv.Itoa(KeyVersion) + "_"
)

// commonMailProviders keep their domain in an email token, so the model still
// sees "a gmail address". Any other domain becomes redactedDomain.
var commonMailProviders = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true,
	"live.com": true, "msn.com": true, "yahoo.com": true, "icloud.com": true, "me.com": true,
	"proton.me": true, "protonmail.com": true, "aol.com": true, "gmx.com": true, "mail.com": true,
}

// Token is one tokenized value. It holds no part of the value except, for a
// common mail provider, the domain, and for a phone, the country calling code.
type Token struct {
	Type   EntityType
	ID     string // "pii1_K7F3A2QZ9MXC", "Person K7F3A2QZ9MXC" or "Address K7F3A2QZ9MXC"
	Prefix string // "+372 " for a phone with a known country code
	Suffix string // "@gmail.com", or "@redacted.invalid" for any other email domain
}

// String is the type and id, for logs and counts.
func (t Token) String() string { return string(t.Type) + ":" + t.ID }

// Surface is the token text that replaces the value on the wire.
func (t Token) Surface() string { return t.Prefix + t.ID + t.Suffix }

// MakeToken builds the deterministic token of a value:
// id = base32(HMAC-SHA256(k_type, Normalize(type, value)))[:12], shaped per
// type (CONTRACT.md and the M5 design, section 3). phoneRegion is used only for
// a PHONE written without +cc. Basalt makes every token: detectors only find spans.
func (k *Keys) MakeToken(t EntityType, value, phoneRegion string) (Token, error) {
	key, ok := k.typeKeys[t]
	if !ok {
		return Token{}, fmt.Errorf("pii: unknown entity type %q", t)
	}
	normalized := Normalize(t, value, phoneRegion)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normalized))
	id := b32.EncodeToString(mac.Sum(nil))[:idChars]

	tok := Token{Type: t, ID: piiPrefix + id}
	switch t {
	case EntityEmail:
		tok.Suffix = "@" + emailTokenDomain(normalized)
	case EntityPhone:
		if _, cc := normalizePhone(value, phoneRegion); cc != 0 {
			tok.Prefix = "+" + strconv.Itoa(int(cc)) + " "
		}
	case EntityPersonName:
		tok.ID = personPrefix + id
	case EntityAddress:
		tok.ID = addressPrefix + id
	case EntityOther:
	}
	return tok, nil
}

func emailTokenDomain(normalized string) string {
	at := strings.LastIndexByte(normalized, '@')
	if at < 0 || !commonMailProviders[normalized[at+1:]] {
		return redactedDomain
	}
	return normalized[at+1:]
}
