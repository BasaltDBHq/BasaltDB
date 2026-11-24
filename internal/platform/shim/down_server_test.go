package shim

import (
	"context"
	"io"
	"testing"
)

// downServer stands in for what basalt mcp answers while the engine is down.
// The tests that use it start an engine that answers, so the fallback is
// never asked; its methods panic if it is. internal/app builds the real one
// and cannot be imported here (it imports this package); shim's external
// tests cover the real one.
type downServer struct{}

func newDownServer(*testing.T) downServer { return downServer{} }

func (downServer) ServeLine(context.Context, io.Writer, []byte) error {
	panic("the fallback answered a line the engine should have")
}

func (downServer) Abandoned(context.Context, io.Writer, []byte) error {
	panic("the fallback answered a request the engine should have")
}
