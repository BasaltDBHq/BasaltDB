package links

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckURL(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{
		"https://portal.basaltvault.app/approvals/x#2.abc-_",
		"http://localhost:8787/a", "http://127.0.0.1", "http://[::1]:80/x", "https://example.com",
	} {
		require.NoError(t, CheckURL(ok), ok)
	}
	for in, pos := range map[string]int{
		"http://localhost:8787/a b": 24, "https://x/\x1b": 11, "https://x/\u009b": 11, "https://x/\x7f": 11,
	} {
		var bad *BadURLError
		require.True(t, errors.As(CheckURL(in), &bad), in)
		require.Equal(t, pos, bad.Pos, in)
	}
	for _, in := range []string{
		"http://localhost:80@evil.com/x", "http://[::1]:1@evil.com", "http://localhost:abc",
		"https://user@example.com", "https://example.com:0", "https://example.com:65536",
		"https://example.com:", "http://localhost:80:90", "http://[::1]x", "http://[::1",
	} {
		require.Error(t, CheckURL(in), in)
	}
	for _, in := range []string{"ftp://x", "http://example.com", "http://localhostx", "https://", "localhost"} {
		require.Error(t, CheckURL(in), in)
	}
	require.Error(t, CheckBase("http://localhost:8787/?q"))
	require.Error(t, CheckBase("https://x/#f"))
	require.NoError(t, CheckBase("http://localhost:8787"))
}
