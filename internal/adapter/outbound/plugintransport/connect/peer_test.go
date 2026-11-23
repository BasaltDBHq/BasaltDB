package connect

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/adaptertest"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// The test binary doubles as the remote plugin: TestMain runs peerMain when
// the first argument is peerFlag. The peer is an httptest TLS server (HTTP/2)
// in its own process, so the adapter's goroutine checks see only the
// adapter, and ExitOnCall is a real server going away mid-call.

const (
	peerFlag = "--peer"
	peerExit = 3
	// echoProcedure is a test-only call: a Struct in, the same Struct out.
	echoProcedure = "/" + pluginv1connect.PluginServiceName + "/Echo"
	echoMethod    = "echo"
	oversizeBytes = pluginproto.MaxMessageBytes + 1024
)

// testMethods adds the suite's echo call to the platform's table.
func testMethods() map[string]method {
	return map[string]method{echoMethod: {
		procedure:   echoProcedure,
		newRequest:  func() proto.Message { return new(structpb.Struct) },
		newResponse: func() proto.Message { return new(structpb.Struct) },
	}}
}

func modeOf(b adaptertest.Behavior) string {
	switch b {
	case adaptertest.Echo:
		return "echo"
	case adaptertest.Oversized:
		return "oversized"
	case adaptertest.Garbage:
		return "garbage"
	case adaptertest.ExitOnCall:
		return "exit"
	case adaptertest.Hang:
		return "hang"
	}
	panic("unknown behavior")
}

// peerService answers the platform calls.
type peerService struct {
	pluginv1connect.UnimplementedPluginServiceHandler
}

func (peerService) Health(context.Context, *connectrpc.Request[pluginv1.HealthRequest]) (*connectrpc.Response[pluginv1.HealthResponse], error) {
	return connectrpc.NewResponse(&pluginv1.HealthResponse{Status: "READY"}), nil
}

// peerHandler is the server for one behavior; in-process tests use it too.
func peerHandler(mode string) http.Handler {
	mux := http.NewServeMux()
	path, h := pluginv1connect.NewPluginServiceHandler(peerService{})
	mux.Handle(path, h)
	mux.Handle(echoProcedure, echoHandler(mode))
	return mux
}

func echoHandler(mode string) http.Handler {
	switch mode {
	case "garbage":
		return http.HandlerFunc(writeGarbage)
	case "exit":
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { os.Exit(peerExit) })
	case "hang":
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	}
	return connectrpc.NewUnaryHandler(echoProcedure,
		func(_ context.Context, req *connectrpc.Request[structpb.Struct]) (*connectrpc.Response[structpb.Struct], error) {
			if mode == "oversized" {
				return connectrpc.NewResponse(&structpb.Struct{Fields: map[string]*structpb.Value{
					"s": structpb.NewStringValue(strings.Repeat("x", oversizeBytes)),
				}}), nil
			}
			return connectrpc.NewResponse(req.Msg), nil
		})
}

// writeGarbage answers with a well-framed gRPC message whose bytes are not a
// protobuf message and carry the marker.
func writeGarbage(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	body := append([]byte{0xff, 0xff, 0xff, 0xff}, adaptertest.GarbageMarker...)
	frame := make([]byte, 5, 5+len(body))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	frame = append(frame, body...)
	w.Header().Set("Content-Type", "application/grpc+proto")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frame)
	w.Header().Set("Grpc-Status", "0")
	w.Header().Set("Grpc-Message", adaptertest.GarbageMarker)
}

// peerMain serves until its stdin closes, then exits. It never returns.
func peerMain(mode string) {
	ts := httptest.NewUnstartedServer(peerHandler(mode))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	out := bufio.NewWriter(os.Stdout)
	_, _ = out.WriteString(ts.URL + "\n" + base64.StdEncoding.EncodeToString(ts.Certificate().Raw) + "\n")
	_ = out.Flush()
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// startPeer runs a peer process and returns its URL, its host:port and a
// pool that trusts its certificate.
func startPeer(t *testing.T, mode string) (url, addr string, roots *x509.CertPool) {
	t.Helper()
	cmd := exec.Command(os.Args[0], peerFlag, mode)
	cmd.Env = []string{}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	br := bufio.NewReader(stdout)
	url = readLine(t, br)
	der, err := base64.StdEncoding.DecodeString(readLine(t, br))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return url, strings.TrimPrefix(url, "https://"), roots
}

func readLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}
