package pages

import "net/http"

// setupNotBuiltMessage is the placeholder setup routes' answer until the
// setup page ships (CONTRACT.md, The local setup page).
const setupNotBuiltMessage = "The setup page is not in this build of basalt yet."

// SetupOnlyHandler is what an engine with no config serves: GET /healthz
// and the setup routes, nothing else. Until the setup page ships, the setup
// routes answer 503 UNAVAILABLE; no route reads a request body.
func SetupOnlyHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	notBuilt := func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", setupNotBuiltMessage)
	}
	mux.HandleFunc("GET /setup/", notBuilt)
	mux.HandleFunc("POST /api/v1/setup/check", notBuilt)
	mux.HandleFunc("POST /api/v1/setup/run", notBuilt)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "This engine has no config yet: it serves only its setup page.")
	})
	return mux
}
