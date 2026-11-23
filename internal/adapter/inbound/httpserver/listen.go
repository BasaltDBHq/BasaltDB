package httpserver

import (
	"fmt"
	"net"
)

const insecurePlaintextHint = "bind loopback, set a TLS certificate and key, or opt in to insecure plaintext"

// listenHost splits a listen address. ok is false when addr is not host:port.
func listenHost(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	return host, true
}

// hostIP parses a listen host as a literal IP. ok is false for hostnames
// (including "localhost"): names are never trusted for listen policy.
func hostIP(host string) (net.IP, bool) {
	if host == "" {
		return net.IPv4zero, true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return ip, true
}

// hostIsUnspecified reports whether host is empty, 0.0.0.0, or :: (every interface).
func hostIsUnspecified(host string) bool {
	ip, ok := hostIP(host)
	return ok && ip.IsUnspecified()
}

func ipIsLoopback(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	return ip.IsLoopback()
}

// addrIsLoopback reports whether addr is a loopback TCP IP.
// Unspecified addresses (0.0.0.0, ::) are not loopback.
func addrIsLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	return ipIsLoopback(tcp.IP)
}

// hostnameBindMismatch reports that a hostname did not resolve to the address
// actually bound. A successful lookup that omits the bound IP is treated as
// rebinding: policy must match the live bind, not the name. Lookup failure
// falls through to the bound-address check only.
func hostnameBindMismatch(host string, bound net.Addr) bool {
	if _, isIP := hostIP(host); isIP {
		return false
	}
	tcp, ok := bound.(*net.TCPAddr)
	if !ok || tcp.IP == nil {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(tcp.IP) {
			return false
		}
	}
	return true
}

// plaintextListenRefused reports whether a plaintext listener is forbidden.
// Policy uses the process bind address only: requested literal IPs before
// Listen, the address actually bound after Listen. Hostnames are not trusted
// as loopback. Forwarded headers are not an input and cannot change this.
func plaintextListenRefused(opts Options, requested string, bound net.Addr) bool {
	if opts.TLSCert != "" || opts.AllowInsecurePlaintext {
		return false
	}
	if bound != nil {
		if !addrIsLoopback(bound) {
			return true
		}
		host, ok := listenHost(requested)
		if !ok {
			return false
		}
		return hostnameBindMismatch(host, bound)
	}
	host, ok := listenHost(requested)
	if !ok {
		return false
	}
	ip, isIP := hostIP(host)
	if !isIP {
		return false
	}
	return !ipIsLoopback(ip)
}

func plaintextListenError(what, addr string) error {
	return fmt.Errorf("plaintext %s listen on %s is reachable from other machines; %s", what, addr, insecurePlaintextHint)
}
