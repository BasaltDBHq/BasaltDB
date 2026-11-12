package vault

import (
	"errors"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Size limits on the engine's socket (CONTRACT.md, Vault channel, Limits).
const (
	// maxControl is the largest control (text) message, 4 KiB.
	maxControl = 4 << 10
	// typeRoute is a ROUTE message's type byte.
	typeRoute byte = 0x10
	// wireVersion is the only version byte.
	wireVersion byte = 0x01
	// sidLen is a session id: 16 random bytes the Vault picks per page socket.
	sidLen = 16
	// routeHeaderLen is version, type and sid in front of a ROUTE payload.
	routeHeaderLen = 2 + sidLen
	// maxRoute is the largest ROUTE message: a frame plus its 18-byte header.
	maxRoute = routeHeaderLen + channel.FrameMax
)

// sid is a session id.
type sid [sidLen]byte

// String is the sid as base64url, as it travels in JSON.
func (s sid) String() string { return b64(s[:]) }

func parseSID(s string) (sid, error) {
	b, err := decodeFixed(s, sidLen)
	if err != nil {
		return sid{}, err
	}
	return sid(b), nil
}

// readBounded reads what is left of a message, but never more than max+1
// bytes of it: over reports a message longer than max, whose excess stays
// unread. Nothing larger than max+1 bytes is ever allocated, whatever the
// sender claims or sends.
func readBounded(r io.Reader, maxLen int) (data []byte, over bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, int64(maxLen)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxLen {
		return nil, true, nil
	}
	return data, false, nil
}

// readRouteHeader reads a ROUTE message's 18-byte header. A version other
// than 1 closes the socket with UNSUPPORTED_VERSION; a short message or
// another type with PROTOCOL.
func readRouteHeader(r io.Reader) (sid, error) {
	var hdr [routeHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return sid{}, closedError{channel.ErrProtocol}
		}
		return sid{}, readErr(err)
	}
	switch {
	case hdr[0] != wireVersion:
		return sid{}, closedError{channel.ErrUnsupportedVersion}
	case hdr[1] != typeRoute:
		return sid{}, closedError{channel.ErrProtocol}
	}
	return sid(hdr[2:]), nil
}
