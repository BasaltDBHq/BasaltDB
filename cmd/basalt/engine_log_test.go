package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// The log basalt engine and basalt mcp write (engineLog) prints a short
// link's secret neither as a string nor inside an error, and an error that
// wraps a link token with %v prints no token.
func TestEngineLogRedactsLinkSecrets(t *testing.T) {
	t.Parallel()
	const secret = "Zm9vYmFyYmF6cXV4cXV1eA"
	var tok channel.LinkToken
	for i := range tok {
		tok[i] = byte(0x61 + i)
	}
	short := links.WithSecret("http://localhost:7300/approvals/0193a4c2-7d1e-7c3a-9f00-0000000000d4", secret)
	var out bytes.Buffer
	log := engineLog(&out)
	log.Info("link", "url", short)
	log.Warn("failed", "err", fmt.Errorf("open %s: refused", short))
	log.Warn("failed", "err", fmt.Errorf("register %v: refused", tok))
	require.NotContains(t, out.String(), secret, out.String())
	require.NotContains(t, out.String(), tok.Wire(), out.String())
	require.Contains(t, out.String(), "#s=[redacted]")
	require.Contains(t, out.String(), "register [redacted]: refused")
}
