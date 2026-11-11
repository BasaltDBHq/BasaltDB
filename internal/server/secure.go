package server

import (
	"net"
	"net/http"

	"github.com/basaltdbhq/basaltdb/internal/websec"
)

const schemeHTTP = "http"

func secureHTTPHandler(opts Options, requestedListen string, ln net.Listener, h http.Handler) http.Handler {
	scheme := schemeHTTP
	if opts.TLSCert != "" {
		scheme = "https"
	}
	allowed := websec.AllowedHostsForListener(requestedListen, ln.Addr())
	return websec.Wrap(h, allowed, scheme, ln.Addr())
}
