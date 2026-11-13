// Package pii holds the engine's PII primitives: keys derived from k_master,
// value normalization, deterministic tokens, the tokenizer that runs a list
// of detectors over text, and the keyed-hash dictionary those detectors look
// values up in. No function here logs or prints a value or a key.
package pii

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// KeyVersion is the key version in token prefixes (pii1_) and HKDF labels.
// Rotation (pii2_) is later work.
const KeyVersion = 1

// MasterKeySize is the length of k_master: 32 random bytes.
const MasterKeySize = 32

// derivedKeySize is the HKDF output length of each derived key (one SHA-256 block).
const derivedKeySize = sha256.Size

// hashSize is how many bytes of the keyed hash a dictionary entry keeps (8, as in the design).
const hashSize = 8

// Hash prefixes keep the generic and typed forms of a value apart.
const (
	genericHashPrefix = "g:"
	typedHashPrefix   = "t:"
)

// Hash is the keyed hash of one normalized value form, as the dictionary
// stores it. It is not reversible without k_master.
type Hash uint64

// Keys holds the per-type token keys and the dictionary key, all derived from
// k_master with HKDF-SHA256. It never exposes or prints key material, and is
// safe for concurrent use (read-only after NewKeys).
type Keys struct {
	version  int
	typeKeys map[EntityType][]byte
	dictKey  []byte
}

// NewKeys derives the keys from k_master (MasterKeySize bytes):
// k_type = HKDF(k_master, "basalt-tok:" + type + ":v1") for every token type
// and k_dict = HKDF(k_master, "basalt-dict:v1"). The caller's slice is not kept.
func NewKeys(master []byte) (*Keys, error) {
	if len(master) != MasterKeySize {
		return nil, fmt.Errorf("pii: master key must be %d bytes, got %d", MasterKeySize, len(master))
	}
	k := &Keys{version: KeyVersion, typeKeys: make(map[EntityType][]byte, len(tokenTypes))}
	for _, t := range tokenTypes {
		dk, err := derive(master, fmt.Sprintf("basalt-tok:%s:v%d", t, KeyVersion))
		if err != nil {
			return nil, err
		}
		k.typeKeys[t] = dk
	}
	dk, err := derive(master, fmt.Sprintf("basalt-dict:v%d", KeyVersion))
	if err != nil {
		return nil, err
	}
	k.dictKey = dk
	return k, nil
}

// derive runs HKDF-SHA256 with no salt: k_master is already uniformly random.
func derive(master []byte, info string) ([]byte, error) {
	dk, err := hkdf.Key(sha256.New, master, nil, info, derivedKeySize)
	if err != nil {
		// The label is not secret; the key is never part of the error.
		return nil, fmt.Errorf("pii: derive key %q: %w", info, err)
	}
	return dk, nil
}

// Version is the key version the keys were derived for.
func (k *Keys) Version() int { return k.version }

// String keeps key material out of logs and %v.
func (k Keys) String() string { return fmt.Sprintf("pii.Keys{v%d, redacted}", k.version) }

// GoString keeps key material out of %#v.
func (k Keys) GoString() string { return k.String() }

// GenericHash is the dictionary hash of a value's generic form in the order
// written, the form word n-grams of free text are looked up by. A dictionary
// stores a value under GenericHashes, which adds the reversed order of a
// two-word name.
func (k *Keys) GenericHash(value string) Hash {
	return k.hash(genericHashPrefix + GenericForm(value))
}

// GenericHashes are the generic-form hashes a value of type t is stored
// under: its generic form, and for a PERSON_NAME of exactly two words the two
// words swapped as well, so free text that names the person surname first
// ("Tamm, Alice", "TAMM Alice") is found at the cost of one more hash per
// such name. Longer names are stored in their own order only: which word is
// the surname is not known.
func (k *Keys) GenericHashes(t EntityType, value string) []Hash {
	form := GenericForm(value)
	hs := []Hash{k.hash(genericHashPrefix + form)}
	if t == EntityPersonName {
		if first, last, ok := strings.Cut(form, " "); ok && !strings.Contains(last, " ") {
			hs = append(hs, k.hash(genericHashPrefix+last+" "+first))
		}
	}
	return hs
}

// TypedHash is the dictionary hash of a value's typed form, the form pattern
// matches (an email, a phone written without spaces) are looked up by.
func (k *Keys) TypedHash(t EntityType, value, phoneRegion string) Hash {
	return k.hash(typedHashPrefix + string(t) + ":" + Normalize(t, value, phoneRegion))
}

// dictionaryCheckForm is hashed with the dictionary key to tell, from the
// dictionary file alone, whether it was built with these keys. Its prefix is
// neither the generic nor the typed one, so it is never a value's hash.
const dictionaryCheckForm = "c:dictionary-key-check"

// dictionaryCheck identifies the dictionary key without revealing it: a file
// whose check differs was built with another k_master and is discarded.
func (k *Keys) dictionaryCheck() uint64 { return uint64(k.hash(dictionaryCheckForm)) }

func (k *Keys) hash(form string) Hash {
	mac := hmac.New(sha256.New, k.dictKey)
	mac.Write([]byte(form))
	return Hash(binary.BigEndian.Uint64(mac.Sum(nil)[:hashSize]))
}
