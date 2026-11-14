package portalverify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/portalverify"
)

// The files checked come from the embedded filesystem itself, so a file
// added to it is checked without a code change.
func TestVerifyChecksEveryFileOfTheFS(t *testing.T) {
	t.Parallel()
	embedded := fstest.MapFS{
		"approve/index.html": {Data: []byte("<html>a</html>")},
		"lib/a.js":           {Data: []byte("export const a = 1")},
		"style.css":          {Data: []byte("body{}")},
	}
	srv := httptest.NewServer(http.FileServer(http.FS(embedded)))
	t.Cleanup(srv.Close)

	r, err := portalverify.Verify(context.Background(), portalverify.Options{Base: srv.URL, Files: embedded})
	require.NoError(t, err)
	require.True(t, r.OK)
	require.Equal(t, 3, r.Checked)

	embedded["lib/new.js"] = &fstest.MapFile{Data: []byte("export const n = 2")}
	r, err = portalverify.Verify(context.Background(), portalverify.Options{Base: srv.URL, Files: embedded})
	require.NoError(t, err)
	require.Equal(t, 4, r.Checked)
	require.True(t, r.OK, "the new file is served too")

	// The same file added only on the binary's side is MISSING on the portal.
	srvOld := httptest.NewServer(http.FileServer(http.FS(fstest.MapFS{
		"approve/index.html": embedded["approve/index.html"], "lib/a.js": embedded["lib/a.js"], "style.css": embedded["style.css"],
	})))
	t.Cleanup(srvOld.Close)
	r, err = portalverify.Verify(context.Background(), portalverify.Options{Base: srvOld.URL, Files: embedded})
	require.NoError(t, err)
	require.False(t, r.OK)
	require.Contains(t, r.Files, portalverify.File{Path: "lib/new.js", Status: portalverify.StatusMissing})
}

func TestValidateURL(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"https://portal.basaltvault.app":  "https://portal.basaltvault.app",
		"https://portal.basaltvault.app/": "https://portal.basaltvault.app",
		"http://127.0.0.1:8080":           "http://127.0.0.1:8080",
		"http://localhost:9":              "http://localhost:9",
		"http://[::1]:9":                  "http://[::1]:9",
	} {
		got, err := portalverify.ValidateURL(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got)
	}
	for _, in := range []string{
		"", "http://portal.basaltvault.app", "http://127.0.0.1.nip.io", "https://", "ftp://x",
		"https://a@b.example", "https://b.example/x", "https://b.example?x=1", "https://b.example#f", "javascript:alert(1)",
	} {
		_, err := portalverify.ValidateURL(in)
		require.Error(t, err, in)
	}
}
