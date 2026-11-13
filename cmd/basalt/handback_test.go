package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

const handBackOrigin = "http://localhost:18788"

var handBackRP = passkey.Relying{RPID: "localhost", Origin: handBackOrigin}

// handBackFixture is a registration request with its hand-back, and the
// body the page posts for it.
func handBackFixture(t *testing.T) (*registrationHandBack, []byte, *passkeytest.Authenticator) {
	t.Helper()
	req, err := passkey.NewRegistrationRequest(rand.Reader, "app", "BasaltDB · app")
	require.NoError(t, err)
	h, err := newRegistrationHandBack(rand.Reader, req, handBackRP)
	require.NoError(t, err)
	person, err := passkeytest.New(handBackRP)
	require.NoError(t, err)
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	return h, body, person
}

// registrationBody is a new authenticator's registration for req, as the
// page posts it.
func registrationBody(t *testing.T, req passkey.RegistrationRequest) ([]byte, *passkeytest.Authenticator) {
	t.Helper()
	a, err := passkeytest.New(handBackRP)
	require.NoError(t, err)
	resp, err := a.Register(req, nil)
	require.NoError(t, err)
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	return body, a
}

// pairingOf is the pairing code the page shows for cred, "XXXX-XXXX".
func pairingOf(t *testing.T, req passkey.RegistrationRequest, cred passkey.Credential) string {
	t.Helper()
	x, y, err := cred.XY()
	require.NoError(t, err)
	return passkey.PairingCode(req.Challenge, cred.ID, x, y)
}

func normalPairing(t *testing.T, code string) string {
	t.Helper()
	n, ok := passkey.NormalizePairingCode(code)
	require.True(t, ok)
	return n
}

func handBackPost(h http.Handler, origin, secret, contentType string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, handBackPath, bytes.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if secret != "" {
		r.Header.Set(links.SecretHeader, secret)
	}
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandBackKeepsAVerifiedPasskey(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	require.Regexp(t, `^[A-Za-z0-9_-]{22}$`, h.secret, "16 random bytes, base64url")

	w := handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"status":"RECEIVED"}`, w.Body.String())
	require.Equal(t, 1, h.count(), "the verified passkey is kept for init")
	cred, n := h.match(normalPairing(t, pairingOf(t, h.req, person.Credential())))
	require.Equal(t, 1, n)
	require.Equal(t, person.Credential().ID, cred.ID)

	w = handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, h.count(), "the same registration posted again is kept once")
}

// TestHandBackRefusesAFifthRegistration: init keeps at most four verified
// registrations; the fifth post is refused and changes nothing.
func TestHandBackRefusesAFifthRegistration(t *testing.T) {
	t.Parallel()
	h, _, _ := handBackFixture(t)
	for i := range maxHandBacks + 1 {
		body, _ := registrationBody(t, h.req)
		w := handBackPost(h, handBackOrigin, h.secret, "application/json", body)
		if i < maxHandBacks {
			require.Equal(t, http.StatusOK, w.Code, "post %d: %s", i+1, w.Body.String())
			continue
		}
		require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
		require.JSONEq(t, `{"code":"RATE_LIMITED","message":"basalt init received more passkeys than it takes"}`, w.Body.String())
	}
	require.Equal(t, maxHandBacks, h.count())
}

// stalledBody is a request body that sends nothing until released.
type stalledBody struct{ release chan struct{} }

func (b stalledBody) Read([]byte) (int, error) {
	<-b.release
	return 0, io.ErrUnexpectedEOF
}

// TestHandBackStalledBodyBlocksNothing: a post with the link's secret
// that never sends its body holds up neither the person's post nor init's
// matching of the typed code.
func TestHandBackStalledBodyBlocksNothing(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	release := make(chan struct{})
	stalled := make(chan int, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPost, handBackPath, stalledBody{release})
		r.Header.Set("Origin", handBackOrigin)
		r.Header.Set(links.SecretHeader, h.secret)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		stalled <- w.Code
	}()
	time.Sleep(50 * time.Millisecond) // let the rogue's post reach the body read

	code := normalPairing(t, pairingOf(t, h.req, person.Credential()))
	var w *httptest.ResponseRecorder
	var cred passkey.Credential
	var n int
	within(t, func() {
		w = handBackPost(h, handBackOrigin, h.secret, "application/json", body)
		cred, n = h.match(code)
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, n)
	require.Equal(t, person.Credential().ID, cred.ID)
	close(release)
	require.Equal(t, http.StatusBadRequest, <-stalled)
	require.Equal(t, 1, h.count())
}

// TestReadRegistrationSaysWhenTheHandBackIsFull: once the hand-back holds
// as many passkeys as it takes, init says to paste the long code.
func TestReadRegistrationSaysWhenTheHandBackIsFull(t *testing.T) {
	t.Parallel()
	h, _, _ := handBackFixture(t)
	person, err := passkeytest.New(handBackRP)
	require.NoError(t, err)
	resp, err := person.Register(h.req, nil)
	require.NoError(t, err)
	long, err := resp.Code()
	require.NoError(t, err)
	stderr := &lockedBuffer{}
	in, typed := io.Pipe()
	c := newIO(context.Background(), stdio{in: in, out: io.Discard, err: stderr}, func(string) string { return "" })
	rogues := make([][]byte, 0, maxHandBacks)
	for range maxHandBacks {
		rogue, _ := registrationBody(t, h.req)
		rogues = append(rogues, rogue)
	}
	go func() {
		for _, rogue := range rogues {
			handBackPost(h, handBackOrigin, h.secret, "application/json", rogue)
		}
		for !strings.Contains(stderr.String(), "received more passkeys than expected") {
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = io.WriteString(typed, long+"\n")
	}()
	var cred passkey.Credential
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Equal(t, 1, strings.Count(stderr.String(), "basalt: basalt init received more passkeys than expected; paste the long code from the page"))
}

func TestHandBackRefuses(t *testing.T) {
	t.Parallel()
	h, body, _ := handBackFixture(t)
	other, err := passkeytest.New(passkey.Relying{RPID: "evil.example", Origin: "https://evil.example"})
	require.NoError(t, err)
	otherResp, err := other.Register(passkey.RegistrationRequest{Challenge: make([]byte, 32)}, nil)
	require.NoError(t, err)
	foreign, err := json.Marshal(otherResp)
	require.NoError(t, err)

	cases := []struct {
		name, origin, secret, contentType string
		body                              []byte
		status                            int
	}{
		{"no origin", "", h.secret, "application/json", body, http.StatusForbidden},
		{"another origin", "http://localhost:9999", h.secret, "application/json", body, http.StatusForbidden},
		{"no secret", handBackOrigin, "", "application/json", body, http.StatusNotFound},
		{"wrong secret", handBackOrigin, strings.Repeat("A", 22), "application/json", body, http.StatusNotFound},
		{"not json", handBackOrigin, h.secret, "text/plain", body, http.StatusUnsupportedMediaType},
		{"too large", handBackOrigin, h.secret, "application/json", bytes.Repeat([]byte(" "), maxHandBackBody+1), http.StatusRequestEntityTooLarge},
		{"not a response", handBackOrigin, h.secret, "application/json", []byte(`{"x":1}`), http.StatusBadRequest},
		{"does not verify", handBackOrigin, h.secret, "application/json", foreign, http.StatusBadRequest},
	}
	for _, tc := range cases {
		w := handBackPost(h, tc.origin, tc.secret, tc.contentType, tc.body)
		require.Equal(t, tc.status, w.Code, "%s: %s", tc.name, w.Body.String())
		var e struct{ Code, Message string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &e), tc.name)
		require.NotEmpty(t, e.Message, tc.name)
	}
	require.Zero(t, h.count(), "nothing reached init")

	// A refused post does not use the secret up.
	w := handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestReadRegistrationTakesThePageHandBack(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	stderr := &lockedBuffer{}
	in, typed := io.Pipe()
	c := newIO(context.Background(), stdio{in: in, out: io.Discard, err: stderr}, func(string) string { return "" })
	code := strings.ToLower(pairingOf(t, h.req, person.Credential()))
	go func() {
		// The registration arrives while init waits, then the person types
		// the code the page shows.
		time.Sleep(50 * time.Millisecond)
		handBackPost(h, handBackOrigin, h.secret, "application/json", body)
		_, _ = io.WriteString(typed, code+"\n")
	}()
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "basalt: Type or paste the code the page shows: ")
	require.Contains(t, stderr.String(), "the code matches the passkey the page sent to basalt init")
}

// TestReadRegistrationNeedsTheCode: the page's post alone registers
// nothing; a closed stdin, with no code typed, ends init.
func TestReadRegistrationNeedsTheCode(t *testing.T) {
	t.Parallel()
	h, body, _ := handBackFixture(t)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", body).Code)
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: io.Discard, err: io.Discard}, func(string) string { return "" })
	var err error
	within(t, func() { _, err = readRegistration(c, h.req, handBackRP, h) })
	require.ErrorContains(t, err, "no passkey code")
}

// freeLocalOrigin is http://localhost:<a port nothing listens on>.
func freeLocalOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return fmt.Sprintf("http://localhost:%d", port)
}

// lockedBuffer is stderr shared with the test reading it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var registerLink = regexp.MustCompile(`/passkeys/register#(1\.[A-Za-z0-9_-]+)`)

// TestInitTakesThePasskeyFromThePage: when init serves the registration
// page, the page posts the passkey back and the person types only the
// short pairing code the page shows.
func TestInitTakesThePasskeyFromThePage(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	origin := freeLocalOrigin(t)
	rp := passkey.Relying{RPID: "localhost", Origin: origin}
	person, err := passkeytest.New(rp)
	require.NoError(t, err)

	stderr := &lockedBuffer{}
	in, typed := io.Pipe()
	c := newIO(context.Background(), stdio{in: in, out: io.Discard, err: stderr},
		func(k string) string { return map[string]string{envAdminURL: d.URL}[k] })
	codes := make(chan int, 1)
	go func() {
		codes <- guardCommands["init"](c, []string{
			"--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
			"--config", filepath.Join(t.TempDir(), "engine.json"), "--os-user", "tester", "--yes", "--passkey-origin", origin,
		})
	}()

	req := handBackFromInit(t, stderr, origin, person)
	_, err = io.WriteString(typed, pairingOf(t, req, person.Credential())+"\n")
	require.NoError(t, err)

	select {
	case code := <-codes:
		require.Equal(t, exitOK, code, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("init did not finish after the person typed the pairing code")
	}
	require.Contains(t, stderr.String(), "passkey registered for localhost")
	require.Equal(t, 1, count(t, d, `SELECT count(credential_id) FROM basalt_meta.passkeys`))
}

// fallbackIO is a cliIO whose stdin is a terminal whose modes cannot be
// set (as on a platform without raw reads): a plain line read of it blocks
// until a line is written to the returned end or the test ends.
func fallbackIO(t *testing.T, stderr io.Writer, raw rawLineReader) (*cliIO, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = w.Close()
		_ = r.Close()
	})
	c := newIO(context.Background(), stdio{in: r, out: io.Discard, err: stderr}, func(string) string { return "" })
	c.terminal = r
	c.rawRead = raw
	return c, w
}

func noRawRead(context.Context, *os.File, []byte) (string, error) { return "", errNoRawRead }

// within fails the test when f does not return in time, instead of
// letting a hang run into the test binary's timeout.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("did not return in time: a read waits for input that never comes")
	}
}

// TestReadRegistrationWithoutRawReads: where the terminal's modes cannot
// be set, the paste is a plain line read that nothing can stop; the page's
// hand-back must still end the wait.
func TestReadRegistrationWithoutRawReads(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	c, typed := fallbackIO(t, io.Discard, noRawRead)
	code := pairingOf(t, h.req, person.Credential())
	go func() {
		time.Sleep(50 * time.Millisecond)
		handBackPost(h, handBackOrigin, h.secret, "application/json", body)
		_, _ = io.WriteString(typed, code+"\n")
	}()
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
}

func TestPasteInBackgroundStopsWithoutRawReads(t *testing.T) {
	t.Parallel()
	c, _ := fallbackIO(t, io.Discard, noRawRead)
	_, stop := c.pasteInBackground(context.Background())
	time.Sleep(20 * time.Millisecond) // let the read start
	within(t, stop)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.pasted(ctx)
	require.ErrorIs(t, err, context.Canceled, "an ended context reads nothing")
}

// TestReadRegistrationReportsAPasteError: a paste that cannot be read is
// said, the person can type the code again, and it is not a wrong try.
func TestReadRegistrationReportsAPasteError(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", body).Code)
	code := pairingOf(t, h.req, person.Credential())
	var stderr lockedBuffer
	// Three unreadable pastes and two wrong codes: only the wrong codes
	// are tries, so the right code still registers.
	lines := []string{"", "", "", "0000-0000", "1111-1111", code}
	reads := 0
	c, _ := fallbackIO(t, &stderr, func(context.Context, *os.File, []byte) (string, error) {
		line := lines[min(reads, len(lines)-1)]
		reads++
		if line == "" {
			return "", errors.New("the pasted text is longer than 64 KiB")
		}
		return line, nil
	})
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "basalt: the pasted code was not read (the pasted text is longer than 64 KiB); type the code again")
}
