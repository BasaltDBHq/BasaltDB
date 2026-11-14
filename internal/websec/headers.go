package websec

import "net/http"

const (
	cspPolicy      = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	frameOptions   = "DENY"
	referrerPolicy = "no-referrer"
	contentTypeOpt = "nosniff"
	// The pages open no other windows and none is meant to reach them: the
	// passkey calls are same-origin WebAuthn in the page itself.
	openerPolicy = "same-origin"
)

// Headers sets browser hardening headers on every response.
func Headers() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", cspPolicy)
			w.Header().Set("X-Frame-Options", frameOptions)
			w.Header().Set("Referrer-Policy", referrerPolicy)
			w.Header().Set("X-Content-Type-Options", contentTypeOpt)
			w.Header().Set("Cross-Origin-Opener-Policy", openerPolicy)
			next.ServeHTTP(w, r)
		})
	}
}

// Expected is the header set Headers sends, for a check that a page served
// from somewhere else (the hosted portal) carries the same policy.
func Expected() http.Header {
	return http.Header{
		"Content-Security-Policy":    {cspPolicy},
		"X-Frame-Options":            {frameOptions},
		"Referrer-Policy":            {referrerPolicy},
		"X-Content-Type-Options":     {contentTypeOpt},
		"Cross-Origin-Opener-Policy": {openerPolicy},
	}
}
