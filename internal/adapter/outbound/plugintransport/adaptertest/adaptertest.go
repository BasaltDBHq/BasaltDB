// Package adaptertest is the suite every plugin transport adapter must pass.
// It is test support: production code never imports it.
//
// An adapter's test supplies a factory that connects to a peer that behaves
// as asked. The suite then holds the adapter to the same rules whatever the
// wire is: failure classes, no payload in an error, prompt return when the
// context ends, concurrent calls kept apart, and no leaked goroutines.
package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// Behavior is how the peer answers calls.
type Behavior int

const (
	// Echo answers every call with a result equal to its params (an object).
	// An adapter's peer may delay answers by a few milliseconds and may
	// answer concurrent calls out of order.
	Echo Behavior = iota
	// Oversized answers with a message larger than protocol.MaxMessageBytes.
	Oversized
	// Garbage answers with bytes that are not a valid reply. The bytes
	// contain GarbageMarker.
	Garbage
	// ExitOnCall ends the peer (the process, or the connection) when the
	// first call arrives, without answering.
	ExitOnCall
	// Hang reads calls and never answers.
	Hang
)

// GarbageMarker is in everything a Garbage peer sends. No error from an
// adapter may contain it: payload text never reaches an error.
const GarbageMarker = "SECRET-PEER-PAYLOAD"

// New connects to a peer with the given behavior and returns the transport.
// It registers its own cleanup with t.
type New func(t *testing.T, b Behavior) pluginhost.Transport

const (
	waitPrompt   = 3 * time.Second // "promptly": far below any peer timer
	cancelAfter  = 50 * time.Millisecond
	leakCalls    = 1000
	leakWorkers  = 8
	spreadMicros = 7 // call deadlines cycle through 0..spreadMicros-1 times 150us
	spreadUnit   = 150 * time.Microsecond
	concCalls    = 64
)

// Run runs the suite against newTransport.
func Run(t *testing.T, newTransport New) {
	t.Helper()
	t.Run("TestEcho", func(t *testing.T) { testEcho(t, newTransport) })
	t.Run("TestConcurrentCallsStayApart", func(t *testing.T) { testConcurrent(t, newTransport) })
	t.Run("TestOversizedResponse", func(t *testing.T) { _ = testFails(t, newTransport, Oversized, pluginhost.ClassBadResponse) })
	t.Run("TestGarbageResponse", func(t *testing.T) { testGarbage(t, newTransport) })
	t.Run("TestChildExit", func(t *testing.T) { testChildExit(t, newTransport) })
	t.Run("TestCancelledContextEndsCall", func(t *testing.T) { testCancel(t, newTransport) })
	t.Run("TestCallAfterClose", func(t *testing.T) { testAfterClose(t, newTransport) })
	t.Run("TestNoGoroutineLeak", func(t *testing.T) { testNoLeak(t, newTransport) })
}

type payload struct {
	N int    `json:"n"`
	S string `json:"s"`
}

func callEcho(ctx context.Context, tr pluginhost.Transport, n int) error {
	in := payload{N: n, S: fmt.Sprintf("v%d", n)}
	var out payload
	if err := tr.Call(ctx, "echo", in, &out); err != nil {
		return err
	}
	if out != in {
		return fmt.Errorf("call %d got another call's answer", n)
	}
	return nil
}

func classOf(err error) pluginhost.FailureClass {
	var c pluginhost.Classed
	if errors.As(err, &c) {
		return c.FailureClass()
	}
	return ""
}

func testEcho(t *testing.T, newTransport New) {
	tr := newTransport(t, Echo)
	if err := callEcho(context.Background(), tr, 1); err != nil {
		t.Fatalf("echo: %v", err)
	}
	// A nil result discards the answer.
	if err := tr.Call(context.Background(), pluginproto.MethodHealth, pluginproto.HealthRequest{}, nil); err != nil {
		t.Fatalf("call with no result: %v", err)
	}
}

func testConcurrent(t *testing.T, newTransport New) {
	tr := newTransport(t, Echo)
	errs := make(chan error, concCalls)
	var wg sync.WaitGroup
	for i := range concCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
			defer cancel()
			errs <- callEcho(ctx, tr, i)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func testFails(t *testing.T, newTransport New, b Behavior, want pluginhost.FailureClass) error {
	t.Helper()
	tr := newTransport(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
	defer cancel()
	var out payload
	err := tr.Call(ctx, "echo", payload{N: 1}, &out)
	if err == nil {
		t.Fatal("the call succeeded")
	}
	if got := classOf(err); got != want {
		t.Fatalf("failure class = %q, want %q (err: %v)", got, want, err)
	}
	return err
}

func testGarbage(t *testing.T, newTransport New) {
	err := testFails(t, newTransport, Garbage, pluginhost.ClassBadResponse)
	if strings.Contains(err.Error(), GarbageMarker) {
		t.Fatalf("the error carries the peer's bytes: %v", err)
	}
}

func testChildExit(t *testing.T, newTransport New) {
	_ = testFails(t, newTransport, ExitOnCall, pluginhost.ClassExited)
}

func testCancel(t *testing.T, newTransport New) {
	tr := newTransport(t, Hang)

	// A context that is already over sends nothing and returns at once.
	done, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := tr.Call(done, "echo", payload{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled before the call: %v", err)
	}

	// A deadline ends a call the peer never answers.
	ctx, cancel := context.WithTimeout(context.Background(), cancelAfter)
	defer cancel()
	start := time.Now()
	err := tr.Call(ctx, "echo", payload{}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if took := time.Since(start); took > waitPrompt {
		t.Fatalf("the call outlived its deadline by %v", took)
	}

	// So does a cancel from another goroutine.
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(cancelAfter, cancel2)
	start = time.Now()
	err = tr.Call(ctx2, "echo", payload{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if took := time.Since(start); took > waitPrompt {
		t.Fatalf("the call outlived its cancel by %v", took)
	}
}

func testAfterClose(t *testing.T, newTransport New) {
	tr := newTransport(t, Echo)
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt)
	defer cancel()
	if err := callEcho(ctx, tr, 1); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call after Close must fail at once, got %v", err)
	}
}

// testNoLeak runs many calls, a share of them cancelled while in flight,
// closes the transport and checks that nothing it started is still running.
func testNoLeak(t *testing.T, newTransport New) {
	opt := goleak.IgnoreCurrent()
	tr := newTransport(t, Echo)

	var wg sync.WaitGroup
	per := leakCalls / leakWorkers
	for w := range leakWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range per {
				n := w*per + i
				// Two calls in three run to completion; the rest get a deadline
				// that usually ends them in flight, or are cancelled first.
				ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
				if n%3 == 0 {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Duration(n%spreadMicros)*spreadUnit)
				}
				if n%5 == 0 {
					cancel() // cancelled before it starts
				}
				// A deadline may cut the call short; only a wrong answer is a failure.
				if err := callEcho(ctx, tr, n); err != nil && ctx.Err() == nil {
					t.Errorf("call %d: %v", n, err)
				}
				cancel()
			}
		}()
	}
	wg.Wait()

	// The transport still works after all that.
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
	defer cancel()
	if err := callEcho(ctx, tr, -1); err != nil {
		t.Fatalf("call after the cancellations: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	goleak.VerifyNone(t, opt)
}
