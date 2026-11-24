package httpsec

import (
	"net"
	"net/http"
	"strings"
)

// Host returns middleware that accepts only allowed hostnames.
func Host(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		set[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if _, ok := set[strings.ToLower(host)]; !ok {
				http.Error(w, "host not allowed: "+host, http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
