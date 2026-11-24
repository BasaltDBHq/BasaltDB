package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
)

// The host reads the engine's build from /healthz: "" from an engine that
// sends none, an error when it does not answer ok.
func TestHostReadsTheEnginesBuild(t *testing.T) {
	t.Parallel()
	with := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(pageserver.BuildHeader, "1.2.3")
		_, _ = w.Write([]byte("ok\n"))
	}))
	t.Cleanup(with.Close)
	without := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }))
	t.Cleanup(without.Close)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	t.Cleanup(broken.Close)

	got, err := osHost{}.EngineBuild(context.Background(), with.URL)
	require.NoError(t, err)
	require.Equal(t, "1.2.3", got)
	got, err = osHost{}.EngineBuild(context.Background(), without.URL)
	require.NoError(t, err)
	require.Empty(t, got)
	_, err = osHost{}.EngineBuild(context.Background(), broken.URL)
	require.Error(t, err)
}
