package httpserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerWrapsAllListeners(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := secureHTTPHandler(Options{}, ln.Addr().String(), ln, inner)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	req.Host = ln.Addr().String()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))

	req.Host = "evil.test"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}
