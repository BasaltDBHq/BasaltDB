package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// handBackPath is the route of the pages basalt init serves where the
// registration page posts the passkey back (CONTRACT.md, CLI).
const handBackPath = "/api/v1/passkeys/register"

// maxHandBackBody bounds the posted registration response (about 1 KiB).
const maxHandBackBody = 16 << 10

// handBackSecretLen is the hand-back secret's length in bytes.
const handBackSecretLen = 16

// registrationHandBack is the hand-back route for one registration
// request: it takes one registration response that verifies against the
// request, from the page's own origin, with the request's secret, and
// hands the verified credential to init.
type registrationHandBack struct {
	req passkey.RegistrationRequest
	rp  passkey.Relying
	// secret is the secret the request carries in the link's fragment;
	// hash is what a post's secret is compared with.
	secret string
	hash   [sha256.Size]byte
	// received gets the verified credential, once.
	received chan passkey.Credential
	mu       sync.Mutex
	used     bool
}

// newRegistrationHandBack draws the secret from rnd and returns the route
// for req, with req.HandBack set to the secret.
func newRegistrationHandBack(rnd io.Reader, req passkey.RegistrationRequest, rp passkey.Relying) (*registrationHandBack, error) {
	b := make([]byte, handBackSecretLen)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return nil, fmt.Errorf("hand-back secret: %w", err)
	}
	secret := passkey.Bytes(b).String()
	req.HandBack = secret
	return &registrationHandBack{
		req: req, rp: rp, secret: secret, hash: sha256.Sum256([]byte(secret)),
		received: make(chan passkey.Credential, 1),
	}, nil
}

// ServeHTTP answers POST handBackPath. Checks, in order: the Origin is the
// page's (403), the secret is the request's and unused (404, the same as
// an unknown route), the body is JSON (415) of at most maxHandBackBody
// bytes (413), it is a registration response (400) and it verifies
// against the request (400). Only a response that verifies uses the
// secret up.
func (h *registrationHandBack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.rp.Origin {
		writeHandBackError(w, http.StatusForbidden, agent.CodePermissionDenied, "the request does not come from the registration page")
		return
	}
	got := sha256.Sum256([]byte(r.Header.Get(links.SecretHeader)))
	h.mu.Lock()
	defer h.mu.Unlock()
	if subtle.ConstantTimeCompare(got[:], h.hash[:]) != 1 || h.used {
		writeHandBackError(w, http.StatusNotFound, agent.CodeNotFound, "this registration link is not the one basalt init is waiting for, or was used already")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeHandBackError(w, http.StatusUnsupportedMediaType, agent.CodeInvalidArgument, "the body must be application/json")
		return
	}
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
	h.used = true
	h.received <- cred
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"RECEIVED"}` + "\n"))
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
