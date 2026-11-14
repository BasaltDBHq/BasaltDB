package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// directAddr is off by default, needs the portal's pages, and listens on
// a loopback IP only (CONTRACT.md, Direct transport).
func TestDirectAddr(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		pages, addr, want, err string
	}{
		{pages: links.Portal, addr: "", want: ""},
		{pages: links.Portal, addr: "off", want: ""},
		{pages: links.Portal, addr: "127.0.0.1:8787", want: "127.0.0.1:8787"},
		{pages: links.Portal, addr: "[::1]:8787", want: "[::1]:8787"},
		{pages: links.Portal, addr: "0.0.0.0:8787", err: "loopback IP only"},
		{pages: links.Portal, addr: ":8787", err: "loopback IP only"},
		{pages: links.Portal, addr: "localhost:8787", err: "loopback IP only"},
		{pages: links.Portal, addr: "127.0.0.1", err: "directAddr"},
		{pages: "http://localhost:8787", addr: "127.0.0.1:8788", err: "needs the portal"},
	} {
		got, err := config.Config{PagesURL: tc.pages, DirectAddr: tc.addr}.Direct()
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.addr)
			continue
		}
		require.NoError(t, err, tc.addr)
		require.Equal(t, tc.want, got)
	}
}
