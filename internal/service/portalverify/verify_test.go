package portalverify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/service/portalverify"
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

// FileHeaders give one page its own policy, at its file's path and at every
// route to it; the other files keep Headers. A wanted Cache-Control must be
// served.
func TestVerifyFileHeaders(t *testing.T) {
	t.Parallel()
	embedded := fstest.MapFS{
		"approve/index.html": {Data: []byte("<html>a</html>")},
		"connect/index.html": {Data: []byte("<html>c</html>")},
	}
	const def, own = "default-src 'self'", "default-src 'self'; connect-src https://c.example"
	serve := func(connectCSP, cacheControl string) string {
		files := http.FileServer(http.FS(embedded))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", def)
			if r.URL.Path == "/connect" || r.URL.Path == "/connect/" {
				w.Header().Set("Content-Security-Policy", connectCSP)
				if cacheControl != "" {
					w.Header().Set("Cache-Control", cacheControl)
				}
			}
			if r.URL.Path == "/connect" {
				_, _ = w.Write(embedded["connect/index.html"].Data)
				return
			}
			files.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	opts := func(base string) portalverify.Options {
		return portalverify.Options{
			Base: base, Files: embedded,
			Headers:     http.Header{"Content-Security-Policy": {def}},
			FileHeaders: map[string]http.Header{"connect/index.html": {"Content-Security-Policy": {own}, "Cache-Control": {"no-store"}}},
			Routes:      []portalverify.Route{{Path: "/connect", File: "connect/index.html"}},
		}
	}

	r, err := portalverify.Verify(context.Background(), opts(serve(own, "private, no-store")))
	require.NoError(t, err)
	require.True(t, r.OK, "%+v", r.Files)

	for name, c := range map[string]struct{ csp, cc, detail string }{
		"the default policy": {def, "no-store", "Content-Security-Policy is"},
		"stored":             {own, "max-age=60", "Cache-Control is"},
		"no Cache-Control":   {own, "", "Cache-Control is"},
	} {
		r, err := portalverify.Verify(context.Background(), opts(serve(c.csp, c.cc)))
		require.NoError(t, err, name)
		require.False(t, r.OK, name)
		got := map[string]portalverify.File{}
		for _, f := range r.Files {
			got[f.Path] = f
		}
		for _, p := range []string{"connect/index.html", "/connect"} {
			require.Equal(t, portalverify.StatusHeader, got[p].Status, "%s: %s", name, p)
			require.Contains(t, got[p].Detail, c.detail, name)
		}
		require.Equal(t, portalverify.StatusOK, got["approve/index.html"].Status, name)
	}
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

func TestParseManifest(t *testing.T) {
	t.Parallel()
	h := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	m, err := portalverify.ParseManifest([]byte(h + "  a.js\r\n" + h + "  b.js\r\n"))
	require.NoError(t, err)
	require.Equal(t, strings.ToLower(h), m["a.js"])
	require.Len(t, m, 2)
	for _, bad := range []string{h + " a.js\n", "zz  a.js\n", h + "  a.js\n" + h + "  a.js\n", strings.Repeat("g", 64) + "  a.js\n"} {
		_, err := portalverify.ParseManifest([]byte(bad))
		require.Error(t, err, bad)
	}
}
