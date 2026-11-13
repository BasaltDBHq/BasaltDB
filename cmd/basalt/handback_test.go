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

func TestHandBackTakesThePasskeyOnce(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	require.Regexp(t, `^[A-Za-z0-9_-]{22}$`, h.secret, "16 random bytes, base64url")

	w := handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"status":"RECEIVED"}`, w.Body.String())
	select {
	case cred := <-h.received:
		require.Equal(t, person.Credential().ID, cred.ID)
	default:
		t.Fatal("the verified passkey was not handed to init")
	}

	w = handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusNotFound, w.Code, "the secret works once")
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
	require.Empty(t, h.received, "nothing reached init")

	// A refused post does not use the secret up.
	w := handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestReadRegistrationTakesThePageHandBack(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	var stderr bytes.Buffer
	// A closed stdin is no answer: init keeps waiting for the page.
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: io.Discard, err: &stderr}, func(string) string { return "" })
	go func() {
		time.Sleep(50 * time.Millisecond)
		handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	}()
	cred, err := readRegistration(c, h.req, handBackRP, h)
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "or paste the code it shows here")
	require.Contains(t, stderr.String(), "the page sent the passkey to basalt init")
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
// page, the page posts the passkey back and nothing is pasted.
func TestInitTakesThePasskeyFromThePage(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	origin := freeLocalOrigin(t)
	rp := passkey.Relying{RPID: "localhost", Origin: origin}
	person, err := passkeytest.New(rp)
	require.NoError(t, err)

	stderr := &lockedBuffer{}
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: io.Discard, err: stderr},
		func(k string) string { return map[string]string{envAdminURL: d.URL}[k] })
	codes := make(chan int, 1)
	go func() {
		codes <- guardCommands["init"](c, []string{
			"--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix,
			"--config", filepath.Join(t.TempDir(), "engine.json"), "--os-user", "tester", "--yes", "--passkey-origin", origin,
		})
	}()

	var frag string
	require.Eventually(t, func() bool {
		m := registerLink.FindStringSubmatch(stderr.String())
		if m != nil {
			frag = m[1]
		}
		return m != nil
	}, 30*time.Second, 20*time.Millisecond, "init printed no registration link")
	req, err := passkey.ParseRegistrationRequest(frag)
	require.NoError(t, err)
	require.NotEmpty(t, req.HandBack, "the link carries the hand-back secret")
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	body, err := json.Marshal(resp)
	require.NoError(t, err)

	post, err := http.NewRequest(http.MethodPost, origin+handBackPath, bytes.NewReader(body))
	require.NoError(t, err)
	post.Header.Set("Origin", origin)
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set(links.SecretHeader, req.HandBack)
	res, err := http.DefaultClient.Do(post)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	require.Equal(t, http.StatusOK, res.StatusCode)

	select {
	case code := <-codes:
		require.Equal(t, exitOK, code, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("init did not finish after the page handed the passkey back")
	}
	require.Contains(t, stderr.String(), "passkey registered for localhost")
	require.Equal(t, 1, count(t, d, `SELECT count(credential_id) FROM basalt_meta.passkeys`))
}

// fallbackIO is a cliIO whose stdin is a terminal whose modes cannot be
// set (as on a platform without raw reads), with nothing ever typed: a
// plain line read of it blocks until the test ends.
func fallbackIO(t *testing.T, stderr io.Writer, raw rawLineReader) *cliIO {
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
	return c
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
	c := fallbackIO(t, io.Discard, noRawRead)
	go func() {
		time.Sleep(50 * time.Millisecond)
		handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	}()
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
}

func TestPasteInBackgroundStopsWithoutRawReads(t *testing.T) {
	t.Parallel()
	c := fallbackIO(t, io.Discard, noRawRead)
	_, stop := c.pasteInBackground(context.Background())
	time.Sleep(20 * time.Millisecond) // let the read start
	within(t, stop)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.pasted(ctx)
	require.ErrorIs(t, err, context.Canceled, "an ended context reads nothing")
}

// TestReadRegistrationReportsAPasteError: a paste that cannot be read is
// said, and the page can still answer.
func TestReadRegistrationReportsAPasteError(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	var stderr lockedBuffer
	c := fallbackIO(t, &stderr, func(context.Context, *os.File, []byte) (string, error) {
		return "", errors.New("the pasted text is longer than 64 KiB")
	})
	go func() {
		time.Sleep(50 * time.Millisecond)
		handBackPost(h, handBackOrigin, h.secret, "application/json", body)
	}()
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "basalt: the pasted code was not read (the pasted text is longer than 64 KiB); waiting for the page")
}
