package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServeHintFindsTheRepoWebDir(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "web", "register"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, webMarker), []byte("<!doctype html>"), 0o600))
	deep := filepath.Join(repo, "cmd", "basalt")
	require.NoError(t, os.MkdirAll(deep, 0o755))

	web := filepath.Join(repo, "web")
	require.Equal(t, web, findWebDir(deep))
	require.Equal(t, "  (the page must be served first; in another terminal: python3 -m http.server 8787 --bind 127.0.0.1 --directory "+
		shellQuote(web)+")\n", serveHint("http://localhost:8787", deep))

	// Outside a checkout: where to run it, and what a 404 means.
	elsewhere := t.TempDir()
	require.Empty(t, findWebDir(elsewhere))
	require.Equal(t, "  (the page must be served first: in the BasaltDB repo run make serve-web PORT=9000; a 404 means the server is not serving the repo's web/)\n",
		serveHint("http://localhost:9000", elsewhere))
	require.Empty(t, findWebDir(""))
}
