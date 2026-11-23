//go:build linux || darwin

package app

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// failingAccepter fails with errs in turn, then reports the listener
// closed.
type failingAccepter struct {
	errs  []error
	calls atomic.Int32
}

func (f *failingAccepter) AcceptUnix() (*net.UnixConn, error) {
	n := int(f.calls.Add(1)) - 1
	if n < len(f.errs) {
		return nil, f.errs[n]
	}
	return nil, net.ErrClosed
}

// Running out of file descriptors does not stop the agent's socket: the
// loop backs off and accepts again. Any other error ends it.
func TestAcceptRetriesATemporaryError(t *testing.T) {
	t.Parallel()
	e := &Engine{log: slog.New(slog.DiscardHandler)}
	emfile := &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	ln := &failingAccepter{errs: []error{emfile, emfile}}
	e.acceptLoop(context.Background(), context.Background(), Agent{Name: "bot"}, ln)
	require.EqualValues(t, 3, ln.calls.Load(), "two retries, then the closed listener ends the loop")

	ln = &failingAccepter{errs: []error{&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EINVAL)}, emfile}}
	e.acceptLoop(context.Background(), context.Background(), Agent{Name: "bot"}, ln)
	require.EqualValues(t, 1, ln.calls.Load(), "a lasting error ends the loop")

	// A cancelled engine stops backing off.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ln = &failingAccepter{errs: []error{emfile, emfile, emfile}}
	done := make(chan struct{})
	go func() { e.acceptLoop(ctx, context.Background(), Agent{Name: "bot"}, ln); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptLoop kept retrying after the engine stopped")
	}
}
