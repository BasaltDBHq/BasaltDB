package engine

import (
	"log/slog"
	"net"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func TestListenPagesRefusesATakenPort(t *testing.T) {
	t.Parallel()
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })
	addr := taken.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	_, err = listenPages(config.Pages{Addr: addr, Origin: "http://localhost:" + port}, slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.Contains(t, err.Error(), "another process holds "+addr)
	require.Contains(t, err.Error(), "lsof -nP -iTCP:"+port+" -sTCP:LISTEN")
	require.Contains(t, err.Error(), "make serve-web")
}

func TestFullCLIFlagsNameTheConfig(t *testing.T) {
	t.Parallel()
	require.Equal(t, "--agent bot --config "+config.DefaultPath(runtime.GOOS), fullCLIFlags("bot", ""))
	require.Equal(t, "--agent bot --config /home/me/engine.json", fullCLIFlags("bot", "--config /home/me/engine.json"))
	require.Equal(t, "--agent bot", cliFlags("bot", ""), "the short form omits the default config")
}

func TestListenPagesServesAFreePort(t *testing.T) {
	t.Parallel()
	site, err := listenPages(config.Pages{Addr: "127.0.0.1:0", Origin: "http://localhost:8787"}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, site.ln.Close())
}
