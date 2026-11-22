package httpsec

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

// PortalCSP is the policy the hosted portal serves its pages with
// (web/_headers; a test fails on drift): the engine's own, plus connect-src
// naming the Vault and nothing else (CONTRACT.md, Vault channel, The page's
// socket), so a short link's page can open its session through
// wss://relay.basaltvault.app. The portal pages never fetch their own
// origin, so connect-src lists no 'self'. The engine's own pages keep
// cspPolicy: they fetch only their own origin and never open the Vault.
const PortalCSP = "default-src 'self'; connect-src wss://relay.basaltvault.app; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// ExpectedPortal is the header set the portal must serve its pages with:
// Expected's, with PortalCSP.
func ExpectedPortal() http.Header {
	h := Expected()
	h.Set("Content-Security-Policy", PortalCSP)
	return h
}

// ConnectPageCSP is the portal's connect page policy (CONTRACT.md, The
// connect page): the pages' policy with connect-src naming the connect
// service, its one other origin. The portal's edge function serves it
// (web/edge/portal.js CONNECT_CSP; a test fails on drift). The engine never
// serves the connect page.
const ConnectPageCSP = "default-src 'self'; connect-src https://connect.basaltvault.app; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// ExpectedConnectPage is the header set the portal must serve the connect
// page with: Expected's, with ConnectPageCSP, and never stored.
func ExpectedConnectPage() http.Header {
	h := Expected()
	h.Set("Content-Security-Policy", ConnectPageCSP)
	h.Set("Cache-Control", "no-store")
	return h
}

// Expected is the header set Headers sends. The hosted portal serves the
// same, with its own CSP (ExpectedPortal).
func Expected() http.Header {
	return http.Header{
		"Content-Security-Policy":    {cspPolicy},
		"X-Frame-Options":            {frameOptions},
		"Referrer-Policy":            {referrerPolicy},
		"X-Content-Type-Options":     {contentTypeOpt},
		"Cross-Origin-Opener-Policy": {openerPolicy},
	}
}
