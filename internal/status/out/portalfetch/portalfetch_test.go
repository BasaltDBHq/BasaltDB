package portalfetch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/status/out/portalfetch"
)

// A GET asks for no cached copy, follows a redirect within the portal's
// origin, reads at most the limit, and names an off-origin redirect as the
// report shows it.
func TestFetcherStaysOnTheOrigin(t *testing.T) {
	t.Parallel()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("elsewhere")) }))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/page", http.StatusFound)
		case "/away":
			http.Redirect(w, r, other.URL+"/page", http.StatusFound)
		case "/page":
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			_, _ = w.Write([]byte(r.Header.Get("Cache-Control") + " body"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f := portalfetch.New(srv.URL)
	ctx := context.Background()

	code, header, body, err := f.Get(ctx, "/moved", 100)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "no-cache body", string(body))
	require.Equal(t, "default-src 'self'", header.Get("Content-Security-Policy"))

	_, _, body, err = f.Get(ctx, "/page", 4)
	require.NoError(t, err)
	require.Equal(t, "no-c", string(body), "the body is read up to the limit")

	code, _, _, err = f.Get(ctx, "/nothing", 100)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, code)

	code, _, body, err = f.Get(ctx, "/away", 100)
	require.EqualError(t, err, "redirected to another origin; not followed")
	require.Zero(t, code)
	require.Empty(t, body)
}
