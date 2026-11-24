package mcpserver_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

func TestTheHelloAnswerSaysWhoOperatesTheEngineAndItsPageOrigin(t *testing.T) {
	t.Parallel()
	answer := func(info mcpserver.Info) mcpserver.Hello {
		var out bytes.Buffer
		require.NoError(t, mcpserver.NewServer(info).Serve(context.Background(), strings.NewReader(string(mcpserver.HelloLine("test"))), &out))
		h, known, ok := mcpserver.HelloAnswer(out.Bytes())
		require.True(t, ok && known, out.String())
		return h
	}
	h := answer(mcpserver.Info{Name: "basalt", Version: "test", OperatedBy: "PERSON", PagesOrigin: "http://localhost:8787"})
	require.Equal(t, "PERSON", h.OperatedBy)
	require.Equal(t, "http://localhost:8787", h.PagesOrigin)

	h = answer(mcpserver.Info{Name: "basalt", Version: "test"})
	require.Empty(t, h.OperatedBy, "a server that says nothing gives the shim nothing to open by")
	require.Empty(t, h.PagesOrigin)
}
