package websec

import "net/http"

const (
	cspPolicy      = "default-src 'self'; frame-ancestors 'none'"
	frameOptions   = "DENY"
	referrerPolicy = "no-referrer"
)

// Headers sets browser hardening headers on every response.
func Headers() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", cspPolicy)
			w.Header().Set("X-Frame-Options", frameOptions)
			w.Header().Set("Referrer-Policy", referrerPolicy)
			next.ServeHTTP(w, r)
		})
	}
}
