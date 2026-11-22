package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServeHintNamesThePort(t *testing.T) {
	t.Parallel()
	require.Equal(t, "  (port 9000 is taken, so basalt init cannot serve this page: stop what holds it (lsof -nP -iTCP:9000 -sTCP:LISTEN), "+
		"or open the link while the engine serves the pages there)\n", serveHint("http://localhost:9000"))
}
