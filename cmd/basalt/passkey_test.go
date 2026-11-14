package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

func TestServeHintNamesThePort(t *testing.T) {
	t.Parallel()
	require.Equal(t, "  (port 9000 is taken, so basalt init cannot serve this page: stop what holds it (lsof -nP -iTCP:9000 -sTCP:LISTEN), "+
		"or open the link while the engine serves the pages there)\n", serveHint("http://localhost:9000"))
}

func TestRelyingParty(t *testing.T) {
	t.Parallel()
	rp, err := relyingParty(links.Portal)
	require.NoError(t, err)
	require.Equal(t, passkey.Relying{RPID: "basaltvault.app", Origin: "https://portal.basaltvault.app"}, rp,
		"the portal signs for RP ID basaltvault.app")
	rp, err = relyingParty(links.DefaultLocal)
	require.NoError(t, err)
	require.Equal(t, passkey.Relying{RPID: "localhost", Origin: "http://localhost:8787"}, rp, "the default: the engine's local pages")
	_, err = relyingParty("https://basaltvault.app")
	require.Error(t, err, "the old hosted origin is gone")
}
