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

// TestInstructionsPointToTheDocs checks the instructions send the agent to the
// docs site (CONTRACT.md, What the agent is told).
func TestInstructionsPointToTheDocs(t *testing.T) {
	t.Parallel()
	require.Contains(t, Instructions, "https://docs.basaltvault.app/llms.txt")
	require.Contains(t, Instructions, "For error codes and troubleshooting, read https://docs.basaltvault.app/llms.txt (each page is also Markdown at its path with .md in place of the trailing slash, e.g. https://docs.basaltvault.app/reference/errors.md).")
}

// TestInstructionsTeachNextSteps checks the instructions tell the agent to
// call status and to follow nextSteps (actionable-errors design, section 5).
func TestInstructionsTeachNextSteps(t *testing.T) {
	t.Parallel()
	for _, want := range []string{
		"Call status at the start of a session",
		"carries nextSteps: do them in order",
		"STOP means do not retry or work around it",
		"When status says operatedBy PERSON, never start, stop, restart or upgrade anything yourself.",
		"Never split a write to avoid a hold",
		"You can never approve a write or sign a revert.",
	} {
		require.Contains(t, Instructions, want)
	}
}

func TestListenPagesServesAFreePort(t *testing.T) {
	t.Parallel()
	site, err := listenPages(config.Pages{Addr: "127.0.0.1:0", Origin: "http://localhost:8787"}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, site.ln.Close())
}
