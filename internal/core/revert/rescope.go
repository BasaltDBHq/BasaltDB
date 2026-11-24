package revert

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// The widen proof (CONTRACT.md, Revert, Rescope, widen and reject).
const (
	RescopePrefix  = "basalt-rescope.1"
	rescopeKeyInfo = "basalt-rescope-key.1"
	// RescopeKeyLen is the length of the key derived from a new link
	// secret; Postgres refuses any other.
	RescopeKeyLen = 32
)

// RescopeKey derives the key the engine passes Postgres for a widen from
// the page's new link secret: HKDF-SHA-256 with an empty salt and info
// "basalt-rescope-key.1". The secret itself never reaches Postgres.
func RescopeKey(newSecret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, newSecret, nil, rescopeKeyInfo, RescopeKeyLen)
}
