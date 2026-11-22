package main

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The registration page server releases its port before stop returns, so
// the engine service init installs next can listen there at once.
func TestServeLocalPagesFreesThePortOnStop(t *testing.T) {
	t.Parallel()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := ln.Addr().(*net.TCPAddr).Port
		require.NoError(t, ln.Close())
		origin := "http://localhost:" + strconv.Itoa(port)
		addr, ok := localPagesAddr(origin)
		require.True(t, ok)

		stop, served := serveLocalPages(origin)
		require.True(t, served)
		stop()
		again, err := net.Listen("tcp", addr)
		require.NoError(t, err, "init still holds %s after stop", addr)
		require.NoError(t, again.Close())
	}
}

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
	require.NoError(t, osHost{}.Probe(context.Background(), socket))
}
