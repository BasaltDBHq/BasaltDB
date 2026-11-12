package links

import (
	"fmt"
	"strconv"
	"strings"
)

// urlChars are the characters the URL rule allows besides letters and
// digits (RFC 3986 unreserved, reserved and the percent sign). Every one is
// between 0x21 and 0x7E (CONTRACT.md, Terminal hyperlinks).
const urlChars = "-._~:/?#[]@!$&'()*+,;=%"

// BadURLError says which character of a URL breaks the URL rule. It holds
// the position only, never the byte: the byte may be a control byte that
// must not reach a terminal.
type BadURLError struct {
	// Pos is the 1-based byte position of the first bad character.
	Pos int
	// Reason says what is wrong when no single character is.
	Reason string
}

func (e *BadURLError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return fmt.Sprintf("character %d is not allowed (use letters, digits and - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; = %% only)", e.Pos)
}

func allowedByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte(urlChars, b) >= 0
}

// CheckURL applies the URL rule: https://, or http:// for a loopback host,
// followed only by RFC 3986 characters. It returns a *BadURLError.
func CheckURL(s string) error {
	for i := 0; i < len(s); i++ {
		if !allowedByte(s[i]) {
			return &BadURLError{Pos: i + 1}
		}
	}
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(s, "http://")
		if !ok {
			return &BadURLError{Pos: 1, Reason: "the URL must start with https:// (or http:// for localhost)"}
		}
		if !loopbackHost(authority(rest)) {
			return &BadURLError{Pos: len("http://") + 1, Reason: "http:// is only for localhost, 127.0.0.1 and [::1]; use https://"}
		}
	}
	auth := authority(rest)
	hostPos := len(s) - len(rest) + 1
	if auth == "" {
		return &BadURLError{Pos: hostPos, Reason: "the URL has no host"}
	}
	if i := strings.IndexByte(auth, '@'); i >= 0 {
		return &BadURLError{Pos: hostPos + i, Reason: fmt.Sprintf("character %d is a user name or password, which a link cannot have", hostPos+i)}
	}
	if !validPort(auth) {
		return &BadURLError{Pos: hostPos, Reason: "the port must be digits from 1 to 65535"}
	}
	return nil
}

// CheckBase applies the URL rule to a pages base, which also has no query
// or fragment.
func CheckBase(s string) error {
	if err := CheckURL(s); err != nil {
		return err
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return &BadURLError{Pos: i + 1, Reason: fmt.Sprintf("character %d starts a query or fragment, which a pages base cannot have", i+1)}
	}
	return nil
}

// authority is the host and port of the text after the scheme.
func authority(rest string) string {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// splitHostPort splits an authority into host and the text after its colon
// (hasPort tells whether there is one). A bracketed host is kept whole.
func splitHostPort(auth string) (host, port string, hasPort, ok bool) {
	if strings.HasPrefix(auth, "[") {
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return "", "", false, false
		}
		host, rest := auth[:end+1], auth[end+1:]
		if rest == "" {
			return host, "", false, true
		}
		port, found := strings.CutPrefix(rest, ":")
		return host, port, true, found
	}
	host, port, hasPort = strings.Cut(auth, ":")
	return host, port, hasPort, !strings.Contains(port, ":")
}

const maxPort = 65535

func validPort(auth string) bool {
	_, port, hasPort, ok := splitHostPort(auth)
	if !ok {
		return false
	}
	if !hasPort {
		return true
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= maxPort
}

func loopbackHost(auth string) bool {
	host, _, _, ok := splitHostPort(auth)
	if !ok {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "[::1]":
		return true
	}
	return false
}
