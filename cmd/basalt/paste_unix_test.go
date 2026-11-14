//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// overLineLimit is longer than the 1024 bytes (MAX_CANON on macOS) a
// terminal in canonical mode holds for one line.
const overLineLimit = 3000

// terminal is a pseudo-terminal: tty is what basalt reads as its stdin,
// and typeIn types into it as the person (or their paste) does.
type terminal struct {
	t      *testing.T
	tty    *os.File
	master *os.File
	mu     sync.Mutex
	shown  bytes.Buffer // what the terminal shows: basalt's echo
}

func newTerminal(t *testing.T) *terminal {
	t.Helper()
	master, tty, err := pty.Open()
	require.NoError(t, err)
	term := &terminal{t: t, tty: tty, master: master}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			term.mu.Lock()
			term.shown.Write(buf[:n])
			term.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = tty.Close()
		_ = master.Close()
		<-done
	})
	return term
}

// canonical reports whether the tty is in canonical mode with echo, as a
// shell leaves it.
func (term *terminal) canonical() bool {
	tio, err := unix.IoctlGetTermios(int(term.tty.Fd()), ttyGetTermios)
	require.NoError(term.t, err)
	return tio.Lflag&unix.ICANON != 0 && tio.Lflag&unix.ECHO != 0
}

// typeIn types s once basalt reads the terminal without the line limit:
// a paste into a canonical-mode line would lose all but its first 1024
// bytes. It fails the test when basalt never does.
func (term *terminal) typeIn(s string) {
	deadline := time.Now().Add(5 * time.Second)
	for term.canonical() {
		if time.Now().After(deadline) {
			term.t.Error("basalt read the terminal in canonical mode: a line over 1024 bytes cannot be pasted")
			_ = term.master.Close() // end the read that would wait for ever
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := io.WriteString(term.master, s)
	require.NoError(term.t, err)
}

func (term *terminal) shownText() string {
	term.mu.Lock()
	defer term.mu.Unlock()
	return term.shown.String()
}

// ptyIO is a cliIO whose stdin is the terminal, as when a person runs
// basalt in a shell.
func ptyIO(term *terminal, stdout, stderr io.Writer) *cliIO {
	c := newIO(context.Background(), stdio{in: term.tty, out: stdout, err: stderr}, func(string) string { return "" })
	c.rand = fixedRand()
	return c
}

// inTime is f's result; the test fails when f does not return in time, so
// a regression to a read that waits for ever fails instead of hanging.
func inTime[T any](t *testing.T, f func() (T, error)) (T, error) {
	t.Helper()
	var v T
	var err error
	within(t, func() { v, err = f() })
	return v, err
}

func longCode() string {
	return "basalt-x.1." + strings.Repeat("A", overLineLimit)
}

func TestPastedReadsALineOverTheTerminalLimit(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	c := ptyIO(term, io.Discard, io.Discard)
	code := longCode()
	go term.typeIn(code + "\r")
	got, err := inTime(t, func() (string, error) { return c.pasted(context.Background()) })
	require.NoError(t, err)
	require.Equal(t, code, got)
	require.True(t, term.canonical(), "the terminal's modes are restored")
	require.Eventually(t, func() bool { return strings.Contains(term.shownText(), code) }, 5*time.Second, 10*time.Millisecond,
		"the paste is echoed")
}

func TestPastedEditsTheLine(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	c := ptyIO(term, io.Discard, io.Discard)
	go term.typeIn("  abx\x7fc\x7f\x7f\x7f\x7f\x7fdef \n")
	got, err := inTime(t, func() (string, error) { return c.pasted(context.Background()) })
	require.NoError(t, err)
	require.Equal(t, "def", got, "backspace erases, surrounding space is trimmed")

	go term.typeIn("\x04")
	_, err = inTime(t, func() (string, error) { return c.pasted(context.Background()) })
	require.ErrorIs(t, err, io.EOF, "Ctrl-D on an empty line ends the input")
	require.True(t, term.canonical())
}

func TestPastedStopsWithItsContext(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	c := ptyIO(term, io.Discard, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		_, err := c.pasted(ctx)
		errs <- err
	}()
	require.Eventually(t, func() bool { return !term.canonical() }, 5*time.Second, 5*time.Millisecond)
	cancel()
	select {
	case err := <-errs:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the read did not stop with its context")
	}
	require.True(t, term.canonical(), "the terminal's modes are restored")
}

func TestPastedKeepsTypedAheadInput(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	c := ptyIO(term, io.Discard, io.Discard)
	_, err := io.WriteString(term.master, "yes\nab")
	require.NoError(t, err)
	answer, err := inTime(t, func() (string, error) { return c.line() })
	require.NoError(t, err)
	require.Equal(t, "yes", answer)
	go term.typeIn("cd\n")
	got, err := inTime(t, func() (string, error) { return c.pasted(context.Background()) })
	require.NoError(t, err)
	require.Equal(t, "abcd", got, "bytes the line reader buffered start the paste")
}

func TestApprovePromptTakesALongCode(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	var stderr bytes.Buffer
	c := ptyIO(term, io.Discard, &stderr)
	code := longCode()
	go term.typeIn(code + "\n")
	got, err := inTime(t, func() (string, error) { return approveCode(c, nil, "") })
	require.NoError(t, err)
	require.Equal(t, code, got)
	require.Contains(t, stderr.String(), "Paste the code the approval page showed: ")
}

// TestApproveOpenTakesALongCode: while basalt approve --open waits for the
// local page, a pasted code over the terminal's line limit is still read.
func TestApproveOpenTakesALongCode(t *testing.T) {
	t.Parallel()
	d, person, cred, _ := revertSetup(t)
	held := holdDelete(t, cred)
	id := held.ApprovalID.String()
	as, err := person.Sign(approval.Challenge(bindingOf(t, cred, held.ApprovalID)), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := approval.NewResponse(held.ApprovalID, as).Code()
	require.NoError(t, err)

	term := newTerminal(t)
	stderr := &lockedBuffer{}
	c := ptyIO(term, io.Discard, stderr)
	h := newFakeHost(t)
	h.pagesUp = true
	c.host = h
	go term.typeIn(strings.Repeat(" ", overLineLimit) + code + "\n")
	exit, _ := inTime(t, func() (int, error) {
		return guardCommands["approve"](c, []string{"--agent", "bot", "--config", localConfig(t, cred), "--open", id}), nil
	})
	require.Equal(t, exitOK, exit, stderr.String())
	require.Contains(t, stderr.String(), "waiting for your signature on the approval page")
	require.Contains(t, stderr.String(), "approval "+id+" signed")
	require.Equal(t, 1, count(t, d, `SELECT count(approval_id)::int FROM basalt_meta.approvals WHERE approved_at IS NOT NULL`))
}

func TestInitPromptTakesALongCode(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	var stderr bytes.Buffer
	c := ptyIO(term, io.Discard, &stderr)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	req, err := passkey.NewRegistrationRequest(fixedRand(), "app", "BasaltDB · app")
	require.NoError(t, err)
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	code, err := resp.Code()
	require.NoError(t, err)
	// Leading spaces (trimmed, as a terminal paste may carry them) make the
	// line longer than the limit whatever the code's own length.
	pasted := strings.Repeat(" ", overLineLimit) + code
	go term.typeIn(pasted + "\n")
	cred, err := inTime(t, func() (passkey.Credential, error) { return readRegistration(c, req, passkey.Production, nil) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "Paste the code the page shows: ")
}

// TestInitPromptTakesAPairingCode: with the hand-back on, the person types
// the short code at a terminal, after a wrong one, and init keeps their
// registration over one another program posted first.
func TestInitPromptTakesAPairingCode(t *testing.T) {
	t.Parallel()
	term := newTerminal(t)
	var stderr bytes.Buffer
	c := ptyIO(term, io.Discard, &stderr)
	h, personBody, person := handBackFixture(t)
	rogueBody, _ := registrationBody(t, h.req)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", rogueBody).Code)
	require.Equal(t, http.StatusOK, handBackPost(h, handBackOrigin, h.secret, "application/json", personBody).Code)
	go term.typeIn("0000-0000\n" + strings.ToLower(pairingOf(t, h.req, person.Credential())) + "\n")
	cred, err := inTime(t, func() (passkey.Credential, error) { return readRegistration(c, h.req, handBackRP, h) })
	require.NoError(t, err)
	require.Equal(t, person.Credential().ID, cred.ID)
	require.Contains(t, stderr.String(), "basalt: that code doesn't match; check the page")
}

func TestPastedWithoutATerminalReadsALine(t *testing.T) {
	t.Parallel()
	c := newIO(context.Background(), stdio{in: strings.NewReader(" abc \nnext\n"), out: io.Discard, err: io.Discard}, func(string) string { return "" })
	got, err := c.pasted(context.Background())
	require.NoError(t, err)
	require.Equal(t, "abc", got)
	got, err = c.line()
	require.NoError(t, err)
	require.Equal(t, "next", got)

	c = newIO(context.Background(), stdio{in: strings.NewReader(""), out: io.Discard, err: io.Discard}, func(string) string { return "" })
	_, err = c.pasted(context.Background())
	require.True(t, errors.Is(err, io.EOF))
}

// awaitCanonical waits until basalt is done with a paste and the terminal is
// back in canonical mode, for the answer to a later prompt.
func (term *terminal) awaitCanonical() {
	deadline := time.Now().Add(5 * time.Second)
	for !term.canonical() {
		if time.Now().After(deadline) {
			term.t.Error("the terminal never left raw input")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPasskeyCheckPromptTakesALongCode(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile, laptop, phone := twoPasskeys(t, d)
	req, err := passkey.NewCheckRequest(fixedRand(), []passkey.Labeled{{CredentialID: laptop.ID, Label: "x"}})
	require.NoError(t, err)
	as, err := laptop.Sign(passkey.CheckChallenge(req.Challenge), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := passkey.CheckResponse{
		Challenge: req.Challenge,
		Found: []passkey.CheckedAssertion{{
			CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
		}},
		Missing: []passkey.Bytes{phone.ID},
	}.Code()
	require.NoError(t, err)

	term := newTerminal(t)
	var stdout, stderr bytes.Buffer
	c := ptyIO(term, &stdout, &stderr)
	go func() {
		term.typeIn(strings.Repeat(" ", overLineLimit) + code + "\n")
		term.awaitCanonical()
		_, _ = io.WriteString(term.master, "n\n") // keep the phone's passkey
	}()
	exit, _ := inTime(t, func() (int, error) {
		return runPasskey(c, []string{"check", "--credential-file", credFile, "--pages-url", links.Portal}), nil
	})
	require.Equal(t, exitOK, exit, stderr.String())
	require.Contains(t, stderr.String(), "Paste the code the page showed: ")
	require.Contains(t, stdout.String(), "found on this device")
}

func TestRevertPromptTakesALongCode(t *testing.T) {
	t.Parallel()
	d, person, cred, run := revertSetup(t)
	term := newTerminal(t)
	var stdout bytes.Buffer
	stderr := &lockedBuffer{}
	c := ptyIO(term, &stdout, stderr)
	go func() {
		var frag string
		deadline := time.Now().Add(30 * time.Second)
		for frag == "" && time.Now().Before(deadline) {
			if m := revertLink.FindStringSubmatch(stderr.String()); m != nil {
				frag = m[1]
			}
			time.Sleep(10 * time.Millisecond)
		}
		if frag == "" {
			t.Error("basalt revert printed no link")
			return
		}
		term.typeIn(strings.Repeat(" ", overLineLimit) + signRevertLink(t, person, frag) + "\n")
	}()
	exit, _ := inTime(t, func() (int, error) {
		return runRevert(c, []string{"--run", run.String(), "--credential-file", cred}), nil
	})
	require.Equal(t, exitOK, exit, stderr.String())
	require.Contains(t, stderr.String(), "Paste the code the revert page showed: ")
	require.Equal(t, "open", leadStatusOf(t, d, 40))
}
