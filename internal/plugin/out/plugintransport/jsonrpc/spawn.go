package jsonrpc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/child"
)

// exitGrace is how long, after the child has exited, the reader may still
// deliver what the child wrote before it did.
const exitGrace = 200 * time.Millisecond

// Spawn starts the plugin s names and talks to it over its stdin and
// stdout. The child runs in its own process group, in s.Dir, with an empty
// environment: nothing of the engine's, and no credentials (s.Env is
// ignored). Its stderr is discarded when s.Stderr is nil, and copied there
// otherwise (the engine passes none).
//
// ctx covers the start only. The child runs until Close, which kills its
// whole process group at once; a graceful stop is the shutdown call, made
// before Close. The transport's Exited channel is closed once the child has
// exited.
func Spawn(ctx context.Context, s child.Spec) (pluginmodel.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("jsonrpc: create pipe: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, fmt.Errorf("jsonrpc: create pipe: %w", err)
	}

	s.Env = nil
	s.Stdin, s.Stdout = inR, outW
	p, err := child.Start(s)
	// The child has its own copies now; ours would keep the pipes open.
	_ = inR.Close()
	_ = outW.Close()
	if err != nil {
		_ = inW.Close()
		_ = outR.Close()
		return nil, fmt.Errorf("jsonrpc: start plugin process: %w", err)
	}

	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = inW.Close()
			p.Stop()
			_ = outR.Close()
		})
	}
	c := newConn(outR, inW, stop)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-p.Exited()
		// What the child wrote before it exited is still in the pipe; give
		// the reader a moment to deliver it before calling the plugin gone.
		select {
		case <-c.done:
		case <-time.After(exitGrace):
			c.abort(pluginmodel.ClassExited)
		}
	}()
	return &spawned{conn: c, p: p}, nil
}

// spawned is a conn to a child process.
type spawned struct {
	*conn
	p *child.Process
}

// Exited is closed once the child has exited.
func (s *spawned) Exited() <-chan struct{} { return s.p.Exited() }
