package httpsec

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// OriginForListener blocks cross-origin state-changing requests unless the Origin
// matches the listener scheme and port and the host is in allowedHosts.
func OriginForListener(scheme string, ln net.Addr, allowedHosts []string) func(http.Handler) http.Handler {
	allowed := hostSet(allowedHosts)
	listenPort := listenerPort(ln)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			u, err := url.Parse(origin)
			if err != nil {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			if u.Scheme != scheme {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			if originPort(u) != listenPort {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			host := strings.ToLower(u.Hostname())
			if _, ok := allowed[host]; !ok {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hostSet(hosts []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		set[h] = struct{}{}
	}
	return set
}

func listenerPort(ln net.Addr) string {
	tcp, ok := ln.(*net.TCPAddr)
	if !ok {
		return ""
	}
	return portString(tcp.Port)
}

func originPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func portString(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}
