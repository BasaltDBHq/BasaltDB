package engineaddr_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engineaddr"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"https://engine.example.com":        "https://engine.example.com",
		"https://engine.example.com/":       "https://engine.example.com",
		"https://a-b.c-d.example:8443":      "https://a-b.c-d.example:8443",
		"https://my-engine.tail1234.ts.net": "https://my-engine.tail1234.ts.net",
		"https://xn--bcher-kva.example":     "https://xn--bcher-kva.example",
		"https://notbasaltvault.app":        "https://notbasaltvault.app",
		"https://2130706433.example":        "https://2130706433.example",
		"https://engine.example.com:65535":  "https://engine.example.com:65535",
	} {
		got, err := engineaddr.Parse(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, in := range []string{
		"", "http://engine.example.com", "https://engine.example.com/path", "https://engine.example.com//",
		"https://engine.example.com?q=1", "https://engine.example.com#f", "https://user@engine.example.com",
		"https://Engine.example.com", "https://engine.example.com.", "https://engine", "https://1.2.3.4",
		"https://[::1]", "https://localhost", "https://localhost.", "https://a.localhost", "https://basaltvault.app",
		"https://portal.basaltvault.app", "https://portal.basaltvault.app.", "https://engine.example.com:443",
		"https://engine.example.com:0", "https://engine.example.com:65536", "https://engine.example.com:08443",
		"https://-bad.example.com", "https://engine.example.com:", " https://engine.example.com",
		"https://0x7f.1", "https://127.1", "https://2130706433", "https://printer.local", "https://db.internal",
		"https://nas.home.arpa", "https://b%C3%BCcher.example", "https://bücher.example", "https://engine.example.123",
	} {
		_, err := engineaddr.Parse(in)
		require.ErrorIs(t, err, engineaddr.ErrInvalid, in)
	}
}
