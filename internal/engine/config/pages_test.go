package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestPagesBase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, url, legacy, want, err string
	}{
		{name: "default: the engine's local pages", want: "http://localhost:8787"},
		{name: "portal", url: "https://portal.basaltvault.app", want: "https://portal.basaltvault.app"},
		{name: "local port", url: "http://localhost:9000/", want: "http://localhost:9000"},
		{name: "older approvalPage key", legacy: "http://localhost:8787/approve/", want: "http://localhost:8787"},
		{name: "pagesUrl wins", url: "http://localhost:9000", legacy: "http://localhost:8787/approve/", want: "http://localhost:9000"},
		{name: "old hosted origin refused", url: "https://basaltvault.app", err: "pagesUrl"},
		{name: "old hosted page refused", legacy: "https://basaltvault.app/approve/", err: "pagesUrl"},
		{name: "a path refused", url: "http://localhost:8787/approvals", err: "pagesUrl"},
		{name: "another host refused", url: "http://example.com:8787", err: "pagesUrl"},
		// The pages, and a passkey's origin, run only at localhost (RP ID
		// localhost): a loopback IP base would open a page that refuses to run.
		{name: "IPv4 loopback refused", url: "http://127.0.0.1:8787", err: `pagesUrl "http://127.0.0.1:8787": the local pages run only at localhost; use http://localhost:8787`},
		{name: "IPv6 loopback refused", url: "http://[::1]:9000", err: `pagesUrl "http://[::1]:9000": the local pages run only at localhost; use http://localhost:9000`},
		{name: "another loopback IP refused", url: "http://127.0.0.2:8787", err: "pagesUrl"},
		{name: "upper-case localhost refused", url: "http://LOCALHOST:8787", err: "use http://localhost:8787"},
		{name: "no port: the default", url: "http://127.0.0.1", err: "use http://localhost:<port>"},
		{name: "older approvalPage on a loopback IP refused", legacy: "http://127.0.0.1:8787/approve/", err: "use http://localhost:8787"},
	} {
		got, err := config.Config{PagesURL: tc.url, ApprovalPage: tc.legacy}.PagesBase()
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

func TestPages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, url, addr string
		want            config.Pages
		err             string
	}{
		{name: "default: on at 127.0.0.1:8787", want: config.Pages{Addr: "127.0.0.1:8787", Origin: "http://localhost:8787"}},
		{name: "portal: off", url: "https://portal.basaltvault.app"},
		{
			name: "local port", url: "http://localhost:9000",
			want: config.Pages{Addr: "127.0.0.1:9000", Origin: "http://localhost:9000"},
		},
		{name: "loopback IP origin refused", url: "http://127.0.0.1:9000", err: "the local pages run only at localhost"},
		{
			name: "explicit IPv6 loopback", addr: "[::1]:8787",
			want: config.Pages{Addr: "[::1]:8787", Origin: "http://localhost:8787"},
		},
		{name: "off", addr: "off"},
		{name: "every interface refused", addr: "0.0.0.0:8787", err: "loopback IP only"},
		{name: "LAN address refused", addr: "192.168.1.10:8787", err: "loopback IP only"},
		{name: "hostname refused", addr: "localhost:8787", err: "loopback IP only"},
		{name: "pages need a local base", url: "https://portal.basaltvault.app", addr: "127.0.0.1:8787", err: "needs a local pagesUrl"},
	} {
		got, err := config.Config{PagesURL: tc.url, PagesAddr: tc.addr}.Pages()
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

func TestLoadRefusesANonLoopbackPagesAddr(t *testing.T) {
	t.Parallel()
	_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "pagesUrl": "http://localhost:8787",
		"pagesAddr": "0.0.0.0:8787", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`, 0o600))
	require.ErrorContains(t, err, "loopback IP only")
}
