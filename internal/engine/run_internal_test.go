package engine

import (
	"log/slog"
	"net"
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

// TestInstructionsCarryTheLinkSentence checks the MCP initialize instructions
// hold the contract's sentence about showing links, unchanged (CONTRACT.md,
// What the agent is told).
func TestInstructionsCarryTheLinkSentence(t *testing.T) {
	t.Parallel()
	require.Contains(t, Instructions, "When you show the person a link from Basalt, put it on its own line exactly as Basalt gave it, "+
		"or as a Markdown link [label](url) with the label from links. Never put a link in a code block or inline code, "+
		"never split, wrap, shorten, encode or rewrite it, and put nothing after it on its line. "+
		"Show personMessage verbatim and keep its line breaks.")
}

func TestListenPagesServesAFreePort(t *testing.T) {
	t.Parallel()
	site, err := listenPages(config.Pages{Addr: "127.0.0.1:0", Origin: "http://localhost:8787"}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, site.ln.Close())
}
