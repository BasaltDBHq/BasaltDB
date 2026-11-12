package channel

import (
	"encoding/binary"
	"errors"
)

// frameHeader is every frame's cleartext header and associated data.
var frameHeader = []byte{wireVersion, typeFrame}

// bucket is the padded size for content of n bytes: max(1024, the next power
// of two >= 4 + n).
func bucket(n int) int {
	size := padMin
	for size < lenPrefix+n {
		size *= 2
	}
	return size
}

// pad is len (4 bytes, big-endian) || content || zero bytes to its bucket.
func pad(content []byte) ([]byte, error) {
	if len(content) > ContentMax {
		return nil, ErrTooLarge
	}
	out := make([]byte, bucket(len(content)))
	binary.BigEndian.PutUint32(out, uint32(len(content)))
	copy(out[lenPrefix:], content)
	return out, nil
}

// unpad refuses every padded plaintext but the canonical one for its len.
func unpad(padded []byte) ([]byte, error) {
	if len(padded) < lenPrefix {
		return nil, ErrFrameInvalid
	}
	n := binary.BigEndian.Uint32(padded)
	if n > ContentMax || len(padded) != bucket(int(n)) {
		return nil, ErrFrameInvalid
	}
	end := lenPrefix + int(n)
	var nonZero byte
	for _, b := range padded[end:] {
		nonZero |= b
	}
	if nonZero != 0 {
		return nil, ErrFrameInvalid
	}
	return padded[lenPrefix:end], nil
}

// errSessionClosed is any use of a session after a refusal or Close.
var errSessionClosed = errors.New("vault channel: session closed")

// Session is one side of an established link session: a sending and a
// receiving direction, each with its own key from Split and its own implicit
// counter. A frame dropped, repeated, reordered, reflected or taken from
// another session fails to open; after any refusal the session refuses
// everything, and the caller closes it with the returned code. A Session is
// not safe for concurrent use. It never prints a key.
type Session struct {
	hash       [hashLen]byte
	send, recv *cipherState
	err        error
}

func newSession(h [hashLen]byte, sendKey, recvKey *[hashLen]byte) (*Session, error) {
	send, err := newCipherState(sendKey)
	if err != nil {
		clear(recvKey[:])
		return nil, err
	}
	recv, err := newCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &Session{hash: h, send: send, recv: recv}, nil
}

// Hash is the final handshake hash h. It may be logged as the session's id;
// it reveals no key.
func (s *Session) Hash() [hashLen]byte { return s.hash }

// Seal pads content and encrypts it as the next frame of this side.
// Content over ContentMax bytes is refused with ErrTooLarge: a larger body
// continues in CONTINUE frames, which is the caller's to split.
func (s *Session) Seal(content []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	padded, err := pad(content)
	if err != nil {
		return nil, err
	}
	defer clear(padded)
	ct, err := s.send.seal(frameHeader, padded)
	if err != nil {
		s.fail(err)
		return nil, err
	}
	return concat(frameHeader, ct), nil
}

// Open checks a received frame in the contract's order: size
// (ErrTooLarge), version (ErrUnsupportedVersion), type (ErrProtocol),
// then decryption with the next counter and canonical padding
// (ErrFrameInvalid). Any refusal ends the session.
func (s *Session) Open(frame []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	content, err := s.open(frame)
	if err != nil {
		s.fail(err)
		return nil, err
	}
	return content, nil
}

func (s *Session) open(frame []byte) ([]byte, error) {
	if len(frame) > FrameMax {
		return nil, ErrTooLarge
	}
	if err := readHeader(frame, typeFrame); err != nil {
		return nil, err
	}
	padded, err := s.recv.open(frame[:headerLen], frame[headerLen:])
	if err != nil {
		return nil, ErrFrameInvalid
	}
	content, err := unpad(padded)
	if err != nil {
		clear(padded)
		return nil, err
	}
	return content, nil
}

// fail ends the session and drops its ciphers.
func (s *Session) fail(err error) {
	s.err = err
	s.send, s.recv = nil, nil
}

// Close ends the session; every later Seal or Open is refused.
func (s *Session) Close() {
	if s.err == nil {
		s.fail(errSessionClosed)
	}
}

// String never shows a key.
func (s *Session) String() string { return "vault channel session " + redacted }

// GoString never shows a key.
func (s *Session) GoString() string { return s.String() }
