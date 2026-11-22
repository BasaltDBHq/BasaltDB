package passkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Bytes is a byte string that travels as base64url without padding (RFC 4648
// §5), the encoding WebAuthn and every approval code use (CONTRACT.md,
// Approvals). encoding/json would otherwise use padded standard base64.
type Bytes []byte

// String returns the base64url text.
func (b Bytes) String() string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// MarshalJSON encodes b as a base64url JSON string.
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

// UnmarshalJSON decodes a base64url JSON string. Padding and the standard
// alphabet are refused so every code has one spelling.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("base64url field: %w", err)
	}
	raw, err := DecodeBase64URL(s)
	if err != nil {
		return err
	}
	*b = raw
	return nil
}

// DecodeBase64URL decodes unpadded base64url text.
func DecodeBase64URL(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return raw, nil
}
