package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// noiseProtocolName is 31 bytes, so h starts as it padded with a zero byte.
const noiseProtocolName = "Noise_NNpsk0_P256_AESGCM_SHA256"

const (
	// nonceLen is AES-GCM's nonce: 4 zero bytes and a big-endian counter.
	nonceLen = 12
	// counterLen is the counter's part of the nonce.
	counterLen = 8
	// maxNonce is Noise's reserved nonce 2^64 - 1, never used.
	maxNonce = ^uint64(0)
)

// errNonceExhausted is the counter at Noise's reserved value. The session
// limits end a session long before; it is a guard, not a path.
var errNonceExhausted = errors.New("vault channel: nonce exhausted")

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// noiseHKDF is Noise's HKDF (section 4.3) with HASHLEN 32, written with HMAC
// so a zero-length input key works as it does in WebCrypto.
func noiseHKDF(ck, ikm []byte, outputs int) [][]byte {
	temp := hmacSHA256(ck, ikm)
	defer clear(temp)
	out := make([][]byte, 0, outputs)
	var prev []byte
	for i := 1; i <= outputs; i++ {
		prev = hmacSHA256(temp, prev, []byte{byte(i)})
		out = append(out, prev)
	}
	return out
}

func noiseNonce(n uint64) []byte {
	nonce := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(nonce[nonceLen-counterLen:], n)
	return nonce
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}

// symmetricState is Noise's SymmetricState with its CipherState (k, n).
// Every token of NNpsk0 comes after psk, so k is set before any payload.
type symmetricState struct {
	ck, h, k [hashLen]byte
	n        uint64
}

func newSymmetricState(prologue []byte) *symmetricState {
	s := &symmetricState{}
	copy(s.h[:], noiseProtocolName)
	s.ck = s.h
	s.mixHash(prologue)
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	m := sha256.New()
	m.Write(s.h[:])
	m.Write(data)
	m.Sum(s.h[:0])
}

func (s *symmetricState) mixKey(ikm []byte) {
	out := noiseHKDF(s.ck[:], ikm, 2)
	copy(s.ck[:], out[0])
	copy(s.k[:], out[1])
	s.n = 0
	clearAll(out)
}

func (s *symmetricState) mixKeyAndHash(ikm []byte) {
	const outputs = 3
	out := noiseHKDF(s.ck[:], ikm, outputs)
	copy(s.ck[:], out[0])
	s.mixHash(out[1])
	copy(s.k[:], out[2])
	s.n = 0
	clearAll(out)
}

// mixE is the e token in psk mode: MixHash, then MixKey, of the 65 bytes as
// they are, with no point check.
func (s *symmetricState) mixE(pub []byte) {
	s.mixHash(pub)
	s.mixKey(pub)
}

func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	aead, err := newGCM(s.k[:])
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, noiseNonce(s.n), plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	aead, err := newGCM(s.k[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, noiseNonce(s.n), ciphertext, s.h[:])
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

// split returns k1 (initiator to responder, page to engine) and k2, and
// erases ck and k: after it only h remains.
func (s *symmetricState) split() (k1, k2 [hashLen]byte) {
	out := noiseHKDF(s.ck[:], nil, 2)
	copy(k1[:], out[0])
	copy(k2[:], out[1])
	clearAll(out)
	s.erase()
	return k1, k2
}

// erase clears the chaining key and the handshake cipher key.
func (s *symmetricState) erase() {
	clear(s.ck[:])
	clear(s.k[:])
}

func clearAll(bufs [][]byte) {
	for _, b := range bufs {
		clear(b)
	}
}

// cipherState is one direction of a session: its AEAD and its counter. The
// counter is the receiver's own and never travels.
type cipherState struct {
	aead cipher.AEAD
	n    uint64
}

func newCipherState(key *[hashLen]byte) (*cipherState, error) {
	aead, err := newGCM(key[:])
	clear(key[:])
	if err != nil {
		return nil, err
	}
	return &cipherState{aead: aead}, nil
}

func (c *cipherState) seal(ad, plaintext []byte) ([]byte, error) {
	if c.n == maxNonce {
		return nil, errNonceExhausted
	}
	ct := c.aead.Seal(nil, noiseNonce(c.n), plaintext, ad)
	c.n++
	return ct, nil
}

func (c *cipherState) open(ad, ciphertext []byte) ([]byte, error) {
	if c.n == maxNonce {
		return nil, errNonceExhausted
	}
	pt, err := c.aead.Open(nil, noiseNonce(c.n), ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	c.n++
	return pt, nil
}
