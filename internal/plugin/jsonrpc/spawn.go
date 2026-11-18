package jsonrpc

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

const (
	// waitDelay bounds how long reaping the child waits for a stderr copy to
	// finish when something else still holds the child's pipes.
	waitDelay = 2 * time.Second
	// exitGrace is how long, after the child has exited, the reader may still
	// deliver what the child wrote before it did.
	exitGrace = 200 * time.Millisecond
)

// Spawn starts the plugin at cmdPath with args and talks to it over its stdin
// and stdout. The child gets an empty environment: nothing of the engine's,
// and no credentials. Its stderr is discarded when stderr is nil, and copied
// to stderr otherwise (the engine passes a writer only under --plugin-debug).
//
// ctx covers the start only. The child runs until Close, which stops it at
// once; a graceful stop is the shutdown call, made before Close.
func Spawn(ctx context.Context, cmdPath string, args []string, stderr io.Writer) (plugin.Transport, error) {
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

	cmd := exec.Command(cmdPath, args...)
	cmd.Env = []string{}
	cmd.Stdin = inR
	cmd.Stdout = outW
	if stderr != nil {
		cmd.Stderr = stderr
	}
	cmd.WaitDelay = waitDelay

	err = cmd.Start()
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
			_ = cmd.Process.Kill()
			_ = outR.Close()
		})
	}
	c := newConn(outR, inW, stop)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		_ = cmd.Wait()
		// What the child wrote before it exited is still in the pipe; give
		// the reader a moment to deliver it before calling the plugin gone.
		select {
		case <-c.done:
		case <-time.After(exitGrace):
			c.abort(plugin.ClassExited)
		}
	}()
	return c, nil
}
