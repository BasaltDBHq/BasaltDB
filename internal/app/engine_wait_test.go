package app

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The health check waits for an engine that comes up after a few failed
// starts, as when launchd restarts it.
func TestProbeWaitsForTheEngine(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("/tmp", "bp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "bot.sock")
	go func() {
		time.Sleep(time.Second)
		ln, err := net.Listen("unix", socket)
		if err != nil {
			return
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"basalt","version":"0"}}}` + "\n"))
	}()
	require.NoError(t, OSHost{}.Probe(context.Background(), socket))
}
