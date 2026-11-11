package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestPages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, page, addr string
		want             config.Pages
		err              string
	}{
		{name: "hosted page: off", page: ""},
		{name: "hosted page explicit: off", page: "https://basaltvault.app/approve/"},
		{name: "local page: on at its port", page: "http://localhost:8787/approve/",
			want: config.Pages{Addr: "127.0.0.1:8787", Origin: "http://localhost:8787"}},
		{name: "loopback IP page", page: "http://127.0.0.1:9000/approve/",
			want: config.Pages{Addr: "127.0.0.1:9000", Origin: "http://127.0.0.1:9000"}},
		{name: "explicit IPv6 loopback", page: "http://localhost:8787/approve/", addr: "[::1]:8787",
			want: config.Pages{Addr: "[::1]:8787", Origin: "http://localhost:8787"}},
		{name: "off", page: "http://localhost:8787/approve/", addr: "off"},
		{name: "every interface refused", page: "http://localhost:8787/approve/", addr: "0.0.0.0:8787", err: "loopback IP only"},
		{name: "LAN address refused", page: "http://localhost:8787/approve/", addr: "192.168.1.10:8787", err: "loopback IP only"},
		{name: "hostname refused", page: "http://localhost:8787/approve/", addr: "localhost:8787", err: "loopback IP only"},
		{name: "pages need a local page", page: "https://basaltvault.app/approve/", addr: "127.0.0.1:8787", err: "needs a local approvalPage"},
		{name: "https localhost is not served", page: "https://localhost:8787/approve/"},
	} {
		got, err := config.Config{ApprovalPage: tc.page, PagesAddr: tc.addr}.Pages()
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
	_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "approvalPage": "http://localhost:8787/approve/",
		"pagesAddr": "0.0.0.0:8787", "agents": [{"name": "a", "osUser": "u", "credentialFile": "/c"}]}`, 0o600))
	require.ErrorContains(t, err, "loopback IP only")
}
