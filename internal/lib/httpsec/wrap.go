package httpsec

import (
	"net"
	"net/http"
	"strings"
)

// Wrap applies Host, Origin, then Headers (request order) around h.
func Wrap(h http.Handler, allowedHosts []string, scheme string, ln net.Addr) http.Handler {
	h = Headers()(h)
	h = OriginForListener(scheme, ln, allowedHosts)(h)
	h = Host(allowedHosts)(h)
	return h
}

// DefaultAllowedHosts returns loopback names and the bind host.
func DefaultAllowedHosts(bindHost string) []string {
	hosts := []string{"127.0.0.1", "localhost", "::1", "[::1]"}
	if h := strings.TrimSpace(bindHost); h != "" {
		hosts = append(hosts, strings.ToLower(h))
	}
	return hosts
}

// ListenHost extracts the host part of a listen address (host:port).
func ListenHost(listenAddr string) string {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return strings.TrimSpace(listenAddr)
	}
	return host
}

// AllowedHostsForListener builds the host allow-list for a bound listener.
func AllowedHostsForListener(requestedListen string, bound net.Addr) []string {
	hosts := DefaultAllowedHosts(ListenHost(requestedListen))
	if tcp, ok := bound.(*net.TCPAddr); ok && tcp.IP != nil && !tcp.IP.IsUnspecified() {
		hosts = append(hosts, strings.ToLower(tcp.IP.String()))
	}
	reqHost := ListenHost(bound.String())
	if isUnspecifiedHost(reqHost) {
		hosts = append(hosts, localInterfaceHosts()...)
	}
	return dedupeHosts(hosts)
}

func isUnspecifiedHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

func localInterfaceHosts() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		out = append(out, strings.ToLower(ipNet.IP.String()))
	}
	return out
}

func dedupeHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
