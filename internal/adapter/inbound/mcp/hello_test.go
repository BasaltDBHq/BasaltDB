package mcp_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
)

func TestTheHelloAnswerSaysWhoOperatesTheEngineAndItsPageOrigin(t *testing.T) {
	t.Parallel()
	answer := func(info mcp.Info) mcp.Hello {
		var out bytes.Buffer
		require.NoError(t, mcp.NewServer(info).Serve(context.Background(), strings.NewReader(string(mcp.HelloLine("test"))), &out))
		h, known, ok := mcp.HelloAnswer(out.Bytes())
		require.True(t, ok && known, out.String())
		return h
	}
	h := answer(mcp.Info{Name: "basalt", Version: "test", OperatedBy: "PERSON", PagesOrigin: "http://localhost:8787"})
	require.Equal(t, "PERSON", h.OperatedBy)
	require.Equal(t, "http://localhost:8787", h.PagesOrigin)

	h = answer(mcp.Info{Name: "basalt", Version: "test"})
	require.Empty(t, h.OperatedBy, "a server that says nothing gives the shim nothing to open by")
	require.Empty(t, h.PagesOrigin)
}
