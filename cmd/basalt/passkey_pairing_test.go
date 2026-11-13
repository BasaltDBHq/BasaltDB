package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// typedIO is a cliIO whose stdin is the lines given (no terminal).
func typedIO(stderr io.Writer, lines ...string) *cliIO {
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	return newIO(context.Background(), stdio{in: in, out: io.Discard, err: stderr}, func(string) string { return "" })
}

// TestInitKeepsTheMatchingRegistration: another program that read the
// link posts its own registration first. Init keeps both, and stores the
// one whose code the person typed from their page, never the rogue's.
func TestInitKeepsTheMatchingRegistration(t *testing.T) {
	t.Parallel()
	h, personBody, person := handBackFixture(t)
	rogueBody, rogue := registrationBody(t, h.req)

	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", rogueBody).Code, "the rogue posts first")
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", personBody).Code, "the person's post is still taken")
	require.Equal(t, 2, h.count())

	personCode := pairingOf(t, h.req, person.Credential())
	require.NotEqual(t, pairingOf(t, h.req, rogue.Credential()), personCode)

	// As typed: lowercase, a space for the dash, spaces around it.
	typed := "  " + strings.ToLower(strings.Replace(personCode, "-", " ", 1)) + " "
	var stderr lockedBuffer
	var cred passkey.Credential
	var err error
	within(t, func() { cred, err = readRegistration(typedIO(&stderr, typed), h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.True(t, person.Credential().PublicKey.Equal(cred.PublicKey), "the person's key, not the rogue's")
	require.Contains(t, stderr.String(), "basalt: Type or paste the code the page shows: ")
}

// TestInitTakesTheCodeAfterAWrongOne: a wrong code is said and counted;
// the right one still registers within the three tries.
func TestInitTakesTheCodeAfterAWrongOne(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", body).Code)
	var stderr lockedBuffer
	var cred passkey.Credential
	var err error
	within(t, func() {
		cred, err = readRegistration(typedIO(&stderr, "0000-0000", "hello", pairingOf(t, h.req, person.Credential())), h.req, handBackRP, h)
	})
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "basalt: that code doesn't match; check the page")
	require.Contains(t, stderr.String(), "basalt: that is not the code the page shows")
}

// TestInitRefusesAfterThreeWrongCodes: three codes that match nothing end
// init, and nothing is stored, even with the person's registration held.
func TestInitRefusesAfterThreeWrongCodes(t *testing.T) {
	t.Parallel()
	h, body, person := handBackFixture(t)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", body).Code)
	right := pairingOf(t, h.req, person.Credential())
	var err error
	within(t, func() {
		_, err = readRegistration(typedIO(io.Discard, "0000-0000", "1111-1111", "basalt-passkey.2.eyJ9", right), h.req, handBackRP, h)
	})
	require.ErrorContains(t, err, "run basalt init again")

	// The whole command: init stores no passkey.
	d := guardtest.New(t).WithDemo(t)
	origin := freeLocalOrigin(t)
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
	atOrigin, err := passkeytest.New(passkey.Relying{RPID: "localhost", Origin: origin})
	require.NoError(t, err)
	handBackFromInit(t, stderr, origin, atOrigin)
	for _, wrong := range []string{"0000-0000", "ZZZZ-ZZZZ", "K7Q2-9MX4"} {
		_, err := io.WriteString(typed, wrong+"\n")
		require.NoError(t, err)
	}
	select {
	case code := <-codes:
		require.NotEqual(t, exitOK, code, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("init did not give up after three wrong codes")
	}
	require.Contains(t, stderr.String(), "run basalt init again")
	require.Equal(t, 0, count(t, d, `SELECT count(credential_id) FROM basalt_meta.passkeys`))
}

// handBackFromInit waits for init's registration link, registers person
// against it and posts the registration back, as the page does.
func handBackFromInit(t *testing.T, stderr *lockedBuffer, origin string, person *passkeytest.Authenticator) passkey.RegistrationRequest {
	t.Helper()
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
	require.NotEmpty(t, req.HandBack)
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
	require.Equal(t, http.StatusOK, res.StatusCode, fmt.Sprintf("hand-back to %s", origin))
	return req
}

// TestInitStillTakesTheLongCode: with the hand-back on, the long
// basalt-passkey.1 code pasted instead still registers (the fallback when
// the page could not post).
func TestInitStillTakesTheLongCode(t *testing.T) {
	t.Parallel()
	h, _, _ := handBackFixture(t)
	person, err := passkeytest.New(handBackRP)
	require.NoError(t, err)
	resp, err := person.Register(h.req, nil)
	require.NoError(t, err)
	long, err := resp.Code()
	require.NoError(t, err)
	var cred passkey.Credential
	within(t, func() { cred, err = readRegistration(typedIO(io.Discard, long), h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Zero(t, h.count(), "nothing was posted")
}
