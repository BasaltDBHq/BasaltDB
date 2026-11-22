package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
