//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/basaltdbhq/basaltdb/internal/approval"
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
		return runGuard(c, append([]string{"approve"}, []string{"--agent", "bot", "--config", localConfig(t, cred), "--open", id}...)), nil
	})
	require.Equal(t, exitOK, exit, stderr.String())
	require.Contains(t, stderr.String(), "waiting for your signature on the approval page")
	require.Contains(t, stderr.String(), "approval "+id+" signed")
	require.Equal(t, 1, count(t, d, `SELECT count(approval_id)::int FROM basalt_meta.approvals WHERE approved_at IS NOT NULL`))
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
