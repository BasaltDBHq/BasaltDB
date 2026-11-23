// Package server holds the listener policy for pages BasaltDB serves over
// HTTP (the approval and revert pages): loopback by default, plaintext
// refused on any other bind unless TLS is set or the operator opts in, and
// the websec Host, Origin and header hardening. It also holds the pidfile
// lock for a long-running process.
package httpserver

import (
	"fmt"
	"net"
	"net/http"
)

// Options are the TLS and plaintext settings for one HTTP listener.
type Options struct {
	TLSCert string
	TLSKey  string
	// AllowInsecurePlaintext is the operator's explicit opt-in to plaintext
	// on a non-loopback bind.
	AllowInsecurePlaintext bool
}

// Wrap is h in the websec hardening for ln, a loopback listener bound
// earlier at addr (one Listen made and handed on).
func Wrap(addr string, ln net.Listener, h http.Handler) http.Handler {
	return secureHTTPHandler(Options{}, addr, ln, h)
}

// Listen binds addr over TCP and returns the listener with h wrapped in the
// websec hardening for that bind. It refuses plaintext on a non-loopback
// bind, checking the requested address before Listen and the address
// actually bound after it. what names the listener in errors.
func Listen(opts Options, what, addr string, h http.Handler) (net.Listener, http.Handler, error) {
	if plaintextListenRefused(opts, addr, nil) {
		return nil, nil, plaintextListenError(what, addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s on %s: %w", what, addr, err)
	}
	if plaintextListenRefused(opts, addr, ln.Addr()) {
		_ = ln.Close()
		return nil, nil, plaintextListenError(what, ln.Addr().String())
	}
	return ln, secureHTTPHandler(opts, addr, ln, h), nil
}
