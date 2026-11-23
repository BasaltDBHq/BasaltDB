package httpserver

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// A waiting engine's listener is served on only when the config's pages
// use its address; any other is closed.
func TestTakeHandedListener(t *testing.T) {
	t.Parallel()
	const waiting = "127.0.0.1:8787"
	require.Nil(t, TakeHandedListener(nil, waiting, waiting))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.Nil(t, TakeHandedListener(ln, waiting, waiting), "bound elsewhere: closed")
	_, err = ln.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.Nil(t, TakeHandedListener(ln, "", waiting), "pages off: closed")
	_, err = ln.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}
