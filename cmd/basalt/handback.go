package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// handBackPath is the route of the pages basalt init serves where the
// registration page posts the passkey back (CONTRACT.md, CLI).
const handBackPath = "/api/v1/passkeys/register"

// maxHandBackBody bounds the posted registration response (about 1 KiB).
const maxHandBackBody = 16 << 10

// handBackReadTimeout bounds reading a post's body.
const handBackReadTimeout = 10 * time.Second

// maxHandBacks is how many verified registrations init keeps per run
// while it waits for the person's pairing code. Another program on the
// machine can read the link and post its own registration first, so init
// keeps more than one and lets the typed code pick; the bound stops a flood.
const maxHandBacks = 4

// codeRateLimited answers a post past maxHandBacks, the code the Vault
// channel uses for the same refusal.
const codeRateLimited = "RATE_LIMITED"

// registrationHandBack is the hand-back route for one registration
// request: it keeps up to maxHandBacks registration responses that verify
// against the request, from the page's own origin, with the request's
// secret. Init stores only the one whose pairing code the person types
// (CONTRACT.md, CLI).
type registrationHandBack struct {
	req  passkey.RegistrationRequest
	rp   passkey.Relying
	hash [sha256.Size]byte
	// mu guards received only: a post reads and verifies its body without
	// it, so a post whose body stalls holds up no other post and no read.
	mu sync.Mutex
	// received holds the verified registrations in arrival order.
	received []handedBack
	// full is closed when received reaches maxHandBacks.
	full chan struct{}
}

// handedBack is one verified registration and its pairing code (the
// canonical 8 characters).
type handedBack struct {
	cred passkey.Credential
	code string
}

// ServeHTTP answers POST handBackPath. Checks, in order: the Origin is the
// page's (403), the secret is the request's (404, the same as an unknown
// route), fewer than maxHandBacks registrations are kept (429), the body is
// JSON (415) of at most maxHandBackBody bytes (413), it is a registration
// response (400) and it verifies against the request (400). Only a
// response that verifies is kept; the same registration posted again is
// kept once. The body is read and verified without the lock, within
// handBackReadTimeout, so a post that stalls its body blocks nothing else.
func (h *registrationHandBack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.rp.Origin {
		writeHandBackError(w, http.StatusForbidden, agent.CodePermissionDenied, "the request does not come from the registration page")
		return
	}
	got := sha256.Sum256([]byte(r.Header.Get(links.SecretHeader)))
	if subtle.ConstantTimeCompare(got[:], h.hash[:]) != 1 {
		writeHandBackError(w, http.StatusNotFound, agent.CodeNotFound, "this registration link is not the one basalt init is waiting for")
		return
	}
	if h.count() >= maxHandBacks {
		writeHandBackFull(w)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeHandBackError(w, http.StatusUnsupportedMediaType, agent.CodeInvalidArgument, "the body must be application/json")
		return
	}
	// The page server's ReadTimeout bounds the body too; this holds when
	// the route is served without it. A writer without deadlines (tests)
	// leaves it to the server.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(handBackReadTimeout))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHandBackBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeHandBackError(w, http.StatusRequestEntityTooLarge, agent.CodeInvalidArgument, "the body is too large")
		return
	case err != nil:
		writeHandBackError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "cannot read the body")
		return
	}
	// The body is the JSON the registration code carries; parsing it as
	// that code reuses the code's strict decoding.
	resp, err := passkey.ParseRegistrationResponse(passkey.RegistrationResponsePrefix + passkey.Bytes(body).String())
	if err != nil {
		writeHandBackError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "the body is not a passkey registration: "+err.Error())
		return
	}
	cred, err := passkey.VerifyRegistration(h.req, resp, h.rp)
	if err != nil {
		writeHandBackError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "the passkey does not verify: "+err.Error())
		return
	}
	x, y, err := cred.XY()
	if err != nil {
		writeHandBackError(w, http.StatusBadRequest, agent.CodeInvalidArgument, "the passkey does not verify: "+err.Error())
		return
	}
	code, _ := passkey.NormalizePairingCode(passkey.PairingCode(h.req.Challenge, cred.ID, x, y)) // always canonical
	if !h.keep(handedBack{cred: cred, code: code}) {
		writeHandBackFull(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"RECEIVED"}` + "\n"))
}

// keep adds r unless it is kept already. It returns false, adding
// nothing, when maxHandBacks are kept.
func (h *registrationHandBack) keep(r handedBack) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if slices.ContainsFunc(h.received, func(k handedBack) bool {
		return bytes.Equal(k.cred.ID, r.cred.ID) && k.cred.PublicKey.Equal(r.cred.PublicKey)
	}) {
		return true
	}
	if len(h.received) >= maxHandBacks {
		return false
	}
	h.received = append(h.received, r)
	if len(h.received) == maxHandBacks {
		close(h.full)
	}
	return true
}

// writeHandBackFull refuses a post past maxHandBacks. The page then shows
// the long code to paste, which init still takes.
func writeHandBackFull(w http.ResponseWriter) {
	writeHandBackError(w, http.StatusTooManyRequests, codeRateLimited, "basalt init received more passkeys than it takes")
}

func writeHandBackError(w http.ResponseWriter, status int, code, message string) {
	body, _ := json.Marshal(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message}) // two strings always marshal
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// count is how many verified registrations are kept.
func (h *registrationHandBack) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.received)
}
