package web_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/web"
)

var connectSrc = regexp.MustCompile(`connect-src ([^;"]+)`)

// The approve and revert pages of a short link read the request from the
// engine and post the signature back (same origin), so their meta CSP must
// allow connect-src 'self'; a browser blocks the fetch otherwise. The
// passkey pages never fetch and keep 'none'.
func TestPageCSPConnectSrc(t *testing.T) {
	cases := map[string]string{
		"approve/index.html":  "'self'",
		"revert/index.html":   "'self'",
		"register/index.html": "'none'",
		"passkeys/index.html": "'none'",
	}
	for page, want := range cases {
		t.Run(page, func(t *testing.T) {
			body, err := web.Files.ReadFile(page)
			require.NoError(t, err)
			m := connectSrc.FindSubmatch(body)
			require.NotNil(t, m, "page has no connect-src in its CSP")
			require.Equal(t, want, string(m[1]))
		})
	}
}
