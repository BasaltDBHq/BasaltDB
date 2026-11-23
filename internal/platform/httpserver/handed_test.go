package httpserver

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// A waiting engine's listener is served on only when the config's pages
// use its address; any other is closed.
func TestTakeHandedListener(t *testing.T) {
	t.Parallel()
	require.Nil(t, TakeHandedListener(nil, setup.PageAddr))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.Nil(t, TakeHandedListener(ln, setup.PageAddr), "bound elsewhere: closed")
	_, err = ln.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.Nil(t, TakeHandedListener(ln, ""), "pages off: closed")
	_, err = ln.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}
