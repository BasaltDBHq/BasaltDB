package websec_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/websec"
)

func TestWrongHostRejected(t *testing.T) {
	t.Parallel()
	h := websec.Host([]string{"127.0.0.1", "localhost"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCrossOriginPostRejected(t *testing.T) {
	t.Parallel()
	h := websec.OriginForListener("http", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}, []string{"127.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/x", nil)
	req.Header.Set("Origin", "http://other:8080")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCLIWithoutOriginAllowed(t *testing.T) {
	t.Parallel()
	h := websec.OriginForListener("http", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}, []string{"127.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestOtherLocalhostPortOriginRejected(t *testing.T) {
	t.Parallel()
	h := websec.OriginForListener("http", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}, []string{"127.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/x", nil)
	req.Header.Set("Origin", "http://127.0.0.1:9090")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestFramingBlocked(t *testing.T) {
	t.Parallel()
	h := websec.Headers()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

func TestWrapOrder(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	allowed := websec.AllowedHostsForListener(ln.Addr().String(), ln.Addr())
	h := websec.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), allowed, "http", ln.Addr())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ln.Addr().String()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusTeapot, w.Code)
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestLocalhostOriginAllowed(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	allowed := websec.AllowedHostsForListener(ln.Addr().String(), ln.Addr())
	h := websec.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), allowed, "http", ln.Addr())

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Host = net.JoinHostPort(host, port)
		req.Header.Set("Origin", "http://"+req.Host)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusNoContent, w.Code, "host %s", host)
	}
}
