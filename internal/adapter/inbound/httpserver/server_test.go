package httpserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenRefusesPlaintextOnEveryInterface(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{":0", "0.0.0.0:0", "[::]:0"} {
		_, _, err := Listen(Options{}, "page", addr, http.NotFoundHandler())
		require.ErrorContains(t, err, "plaintext", addr)
	}
}

func TestListenAllowsLoopback(t *testing.T) {
	t.Parallel()
	ln, h, err := Listen(Options{}, "page", "127.0.0.1:0", http.NotFoundHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	require.NotNil(t, h)
}

func TestListenInsecureOptIn(t *testing.T) {
	t.Parallel()
	ln, _, err := Listen(Options{AllowInsecurePlaintext: true}, "page", "0.0.0.0:0", http.NotFoundHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
}
