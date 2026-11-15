package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// A session another goroutine ends is taken first and closed next. Serve
// sees it gone in between; waiting with ended keeps the socket for that
// close, so the page reads the session's code, not a dropped socket.
func TestDirectCarrierKeepsTheEndersCode(t *testing.T) {
	t.Parallel()
	waited := make(chan time.Duration, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		out := newDirectCarrier(ws)
		ctx := context.WithoutCancel(r.Context())
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = out.closeSession(ctx, sid{}, channel.ErrLinkRefused)
		}()
		start := time.Now()
		out.ended()
		waited <- time.Since(start)
		out.wait()
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err)
	defer func() { _ = ws.CloseNow() }()
	_, _, err = ws.Read(ctx)
	require.Equal(t, websocket.StatusCode(channel.ErrLinkRefused), websocket.CloseStatus(err))
	// ended returned on the close starting, not on its timeout.
	require.Less(t, <-waited, writeTimeout/2)
}
