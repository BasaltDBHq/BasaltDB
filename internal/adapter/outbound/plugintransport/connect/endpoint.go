package connect

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// transportName is the only transport a remote endpoint may name.
const transportName = "connectrpc"

const defaultHTTPSPort = "443"

// The reasons Dial refuses an endpoint before connecting. Each comes wrapped
// with the endpoint's host, and with nothing else from the URL: a URL may
// hold a user name or password, so it is never printed.
var (
	// ErrEndpointURL: the URL does not parse, is not https, names no host or
	// carries a user name, password, query or fragment, or the endpoint names
	// another transport.
	ErrEndpointURL = errors.New("the endpoint is not a valid connectrpc https URL")
	// ErrPlainHTTP: the URL is http://. TLS is always required.
	ErrPlainHTTP = errors.New("plain http is refused; a remote plugin must use https")
	// ErrNotInEgress: the URL's host and port (443 when it names none) are
	// not exactly one of the plugin's egress entries.
	ErrNotInEgress = errors.New("the endpoint's host and port are not in the plugin's egress")
	// ErrCertificate: the server's TLS certificate does not verify for the
	// URL's host against the system roots.
	ErrCertificate = errors.New("the server's TLS certificate is not valid for the endpoint's host")
	// ErrUnreachable: no TLS connection could be made to the endpoint.
	ErrUnreachable = errors.New("the endpoint cannot be reached")
)

// target is a checked remote endpoint.
type target struct {
	// host is the URL's host name, lowercase, without brackets or port. It
	// is the only part of the URL an error may show.
	host string
	// addr is host:port, the one address the engine connects to.
	addr string
	// baseURL is https://addr plus the URL's path, without a trailing slash.
	baseURL string
}

// endpointError is a refusal naming the endpoint's host only.
func endpointError(host string, reason error) error {
	if host == "" {
		return fmt.Errorf("connect: endpoint: %w", reason)
	}
	return fmt.Errorf("connect: endpoint %s: %w", host, reason)
}

// checkEndpoint applies the rules for a remote endpoint that need no
// network: https only, no credentials, query or fragment in the URL, and the
// URL's host and port in egress. It never returns the URL's text.
func checkEndpoint(ep pluginmodel.RemoteEndpoint, egress []string) (target, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return target{}, endpointError("", ErrEndpointURL)
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme == "http":
		return target{}, endpointError(host, ErrPlainHTTP)
	case u.Scheme != "https", ep.Transport != transportName, host == "",
		u.User != nil, u.Opaque != "", u.RawQuery != "", u.ForceQuery, u.Fragment != "":
		return target{}, endpointError(host, ErrEndpointURL)
	}
	port := u.Port()
	if port == "" {
		port = defaultHTTPSPort
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return target{}, endpointError(host, ErrEndpointURL)
	}
	addr := net.JoinHostPort(host, port)
	if !inEgress(addr, egress) {
		return target{}, endpointError(host, ErrNotInEgress)
	}
	return target{
		host:    host,
		addr:    addr,
		baseURL: "https://" + addr + strings.TrimSuffix(u.EscapedPath(), "/"),
	}, nil
}

// inEgress reports whether addr is exactly one of the egress entries.
// Entries are lowercase by the manifest's rules; case is ignored all the
// same.
func inEgress(addr string, egress []string) bool {
	for _, e := range egress {
		if strings.EqualFold(e, addr) {
			return true
		}
	}
	return false
}
