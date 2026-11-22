package httpserver

import (
	"net"
	"net/http"

	"github.com/basaltdbhq/basaltdb/internal/lib/httpsec"
)

const schemeHTTP = "http"

func secureHTTPHandler(opts Options, requestedListen string, ln net.Listener, h http.Handler) http.Handler {
	scheme := schemeHTTP
	if opts.TLSCert != "" {
		scheme = "https"
	}
	allowed := httpsec.AllowedHostsForListener(requestedListen, ln.Addr())
	return httpsec.Wrap(h, allowed, scheme, ln.Addr())
}
