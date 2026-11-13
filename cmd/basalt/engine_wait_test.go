package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
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

func TestInitNamesTheEngineLogErrorWhenTheEngineNeverAnswers(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.probeErr = errors.New("connect: no such file or directory")
	h.engineLog = "time=1 level=INFO msg=\"engine starting\"\n" +
		"time=2 level=ERROR msg=\"listen pages on 127.0.0.1:8787: address already in use\"\n" +
		"time=3 level=INFO msg=\"engine stopped\"\n\n"
	r := initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "the engine did not answer on /run/basalt/bot.sock")
	require.Contains(t, r.stderr, `its log's last error: time=2 level=ERROR msg="listen pages on 127.0.0.1:8787: address already in use"`)
}

func TestLastEngineError(t *testing.T) {
	t.Parallel()
	require.Empty(t, lastEngineError(""))
	require.Equal(t, "panic: boom", lastEngineError("ok\npanic: boom\n\n"), "no error line: the last line")
	require.Equal(t, `{"level":"ERROR","msg":"x"}`, lastEngineError(`{"level":"ERROR","msg":"x"}`+"\n"+`{"level":"INFO","msg":"y"}`))
	long := "level=ERROR msg=" + strings.Repeat("x", 1000)
	require.Equal(t, long[:maxEngineLogLine]+"…", lastEngineError(long+"\n"), "a long line is cut")
	require.Equal(t, "level=ERROR msg=<U+001B>[31m", lastEngineError("level=ERROR msg=\x1b[31m\n"), "made safe for the terminal")
}
