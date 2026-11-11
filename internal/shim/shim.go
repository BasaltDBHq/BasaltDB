// Package shim is the agent's MCP server process: it relays the MCP client's
// stdio to the engine's Unix socket for that agent and back. It holds no
// secret and never parses SQL, so it starts instantly and has nothing an
// agent could take from it.
package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

// Relay connects to socketPath and copies in to the socket and the socket to
// out. When in ends, the write side of the socket is closed so the engine
// finishes its responses; Relay returns when the engine closes the
// connection or ctx is done.
func Relay(ctx context.Context, socketPath string, in io.Reader, out io.Writer) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to the basalt engine at %s (is the engine service running?): %w", socketPath, err)
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return fmt.Errorf("%s is not a Unix socket", socketPath)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	go func() {
		// A failed copy from the client ends the session the same way EOF
		// does: the engine sees the write side close.
		_, _ = io.Copy(conn, in)
		_ = conn.CloseWrite()
	}()
	_, err = io.Copy(out, conn)
	if err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("relay from engine: %w", err)
	}
	return nil
}
