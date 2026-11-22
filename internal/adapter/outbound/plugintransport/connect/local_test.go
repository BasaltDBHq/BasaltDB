package connect

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/adaptertest"
	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	plugin "github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// shortDir returns a fresh directory with a short path: a Unix socket path
// has a small length limit, and t.TempDir's is too long on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func h2cServer(h http.Handler) *http.Server {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Server{Handler: h, Protocols: &p}
}

// localPeerMain is the peer process for a local plugin: it serves h2c on the
// socket until its stdin closes.
func localPeerMain(mode, sock string) {
	l, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(2)
	}
	srv := h2cServer(peerHandler(mode))
	go func() { _ = srv.Serve(l) }()
	out := bufio.NewWriter(os.Stdout)
	_, _ = out.WriteString("ready\n")
	_ = out.Flush()
	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			os.Exit(0)
		}
	}
}

func startLocalPeer(t *testing.T, mode string) string {
	t.Helper()
	sock := filepath.Join(shortDir(t), "p.sock")
	cmd := exec.Command(os.Args[0], peerFlag, mode, sock)
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
	readLine(t, bufio.NewReader(stdout))
	return sock
}

func TestLocalAdapter(t *testing.T) {
	adaptertest.Run(t, func(t *testing.T, b adaptertest.Behavior) plugin.Transport {
		t.Helper()
		sock := startLocalPeer(t, modeOf(b))
		tr, err := dialLocal(context.Background(), sock, options{methods: testMethods()})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		return tr
	})
}

// localServer is an in-process h2c server on a socket that records what
// reaches it.
type localServer struct {
	sock string

	mu      sync.Mutex
	headers []http.Header
	protos  []int
}

func (s *localServer) seen() ([]http.Header, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.headers...), append([]int(nil), s.protos...)
}

func newLocalServer(t *testing.T, h http.Handler) *localServer {
	t.Helper()
	s := &localServer{sock: filepath.Join(shortDir(t), "s.sock")}
	l, err := net.Listen("unix", s.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := h2cServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.headers = append(s.headers, r.Header.Clone())
		s.protos = append(s.protos, r.ProtoMajor)
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func dialLocalServer(t *testing.T, s *localServer) plugin.Transport {
	t.Helper()
	tr, err := dialLocal(context.Background(), s.sock, options{methods: testMethods()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestLocalSpeaksGRPC(t *testing.T) {
	s := newLocalServer(t, peerHandler("echo"))
	tr := dialLocalServer(t, s)
	var got protocol.HealthResponse
	if err := tr.Call(context.Background(), protocol.MethodHealth, protocol.HealthRequest{}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "READY" {
		t.Fatalf("status = %q", got.Status)
	}

	// The stock gRPC client reaches the same handler the same way.
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	hc := &http.Client{Transport: &http.Transport{
		Protocols: &p,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", s.sock)
		},
	}}
	t.Cleanup(hc.CloseIdleConnections)
	stock := pluginv1connect.NewPluginServiceClient(hc, "http://localhost", connectrpc.WithGRPC())
	res, err := stock.Health(context.Background(), connectrpc.NewRequest(&pluginv1.HealthRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetStatus() != "READY" {
		t.Fatalf("stock client status = %q", res.Msg.GetStatus())
	}

	headers, protos := s.seen()
	if len(headers) != 2 {
		t.Fatalf("the server saw %d requests", len(headers))
	}
	for i, h := range headers {
		if ct := h.Get("Content-Type"); ct != "application/grpc" && ct != "application/grpc+proto" {
			t.Fatalf("request %d content type %q", i, ct)
		}
		if protos[i] != 2 {
			t.Fatalf("request %d over HTTP/%d", i, protos[i])
		}
	}
	if headers[0].Get("Content-Type") != headers[1].Get("Content-Type") {
		t.Fatalf("the adapter sent %q, the stock gRPC client %q", headers[0].Get("Content-Type"), headers[1].Get("Content-Type"))
	}
}

func TestLocalSendsNoCredential(t *testing.T) {
	s := newLocalServer(t, peerHandler("echo"))
	tr := dialLocalServer(t, s)
	if err := tr.Call(context.Background(), protocol.MethodHealth, nil, nil); err != nil {
		t.Fatal(err)
	}
	headers, _ := s.seen()
	if len(headers) != 1 {
		t.Fatalf("the server saw %d requests", len(headers))
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		if v := headers[0].Get(name); v != "" {
			t.Fatalf("%s header sent: %q", name, v)
		}
	}
}

// The transport dials the socket whatever address the request names, and
// never opens a TCP connection, even with a proxy set in the environment.
func TestLocalNeverDialsTCP(t *testing.T) {
	var tcpHits atomic.Int64
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			tcpHits.Add(1)
			_ = c.Close()
		}
	}()
	t.Setenv("HTTP_PROXY", "http://"+tl.Addr().String())
	t.Setenv("http_proxy", "http://"+tl.Addr().String())
	t.Setenv("ALL_PROXY", "http://"+tl.Addr().String())

	// A redirect to the TCP listener is not followed either.
	s := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+tl.Addr().String()+"/x", http.StatusFound)
	}))
	tr := dialLocalServer(t, s)
	err = tr.Call(context.Background(), protocol.MethodHealth, nil, nil)
	if got := classOf(err); got != plugin.ClassBadResponse {
		t.Fatalf("redirect: class %q, err %v", got, err)
	}

	// Whatever URL a request carries, the dial goes to the socket.
	lc := tr.(*conn)
	for _, addr := range []string{tl.Addr().String(), "example.com:80"} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/p", nil)
		if resp, err := lc.transport.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
		}
	}
	headers, _ := s.seen()
	if len(headers) < 3 {
		t.Fatalf("the socket saw %d requests, want every one of them", len(headers))
	}
	if n := tcpHits.Load(); n != 0 {
		t.Fatalf("%d TCP connections were opened", n)
	}
}

func TestLocalRefusesWhatIsNotASocket(t *testing.T) {
	dir := shortDir(t)
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newLocalServer(t, peerHandler("echo"))
	link := filepath.Join(dir, "l")
	if err := os.Symlink(s.sock, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, dir, link, filepath.Join(dir, "missing"), ""} {
		_, err := DialLocal(context.Background(), path)
		if !errors.Is(err, ErrNotSocket) {
			t.Fatalf("%q: err = %v, want ErrNotSocket", path, err)
		}
		if strings.Contains(err.Error(), dir) {
			t.Fatalf("the error carries the directory: %v", err)
		}
	}
}

func TestLocalDeadSocketIsUnreachable(t *testing.T) {
	sock := filepath.Join(shortDir(t), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close() // the file stays, nobody listens
	_, err = DialLocal(context.Background(), sock)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestLocalInstancesShareNothing(t *testing.T) {
	a := newLocalServer(t, peerHandler("echo"))
	b := newLocalServer(t, peerHandler("echo"))
	ta := dialLocalServer(t, a)
	tb := dialLocalServer(t, b)
	if err := ta.Call(context.Background(), protocol.MethodHealth, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = ta.Close()
	if err := tb.Call(context.Background(), protocol.MethodHealth, nil, nil); err != nil {
		t.Fatalf("closing one entry broke the other: %v", err)
	}
	if h, _ := a.seen(); len(h) != 1 {
		t.Fatalf("first socket saw %d requests", len(h))
	}
	if h, _ := b.seen(); len(h) != 1 {
		t.Fatalf("second socket saw %d requests", len(h))
	}
}

func TestLocalContextEndsTheCall(t *testing.T) {
	release := make(chan struct{})
	s := newLocalServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release) })
	tr := dialLocalServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := tr.Call(ctx, protocol.MethodHealth, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the call took %v to end", d)
	}
}

// TestLocalRechecksTheSocketOnEveryConnection: the HTTP transport opens new
// connections on its own. After the first one ends, a symbolic link put at
// the socket's path, to another live socket, is refused, and that socket
// never sees a request.
func TestLocalRechecksTheSocketOnEveryConnection(t *testing.T) {
	sock := filepath.Join(shortDir(t), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	first := h2cServer(peerHandler("echo"))
	go func() { _ = first.Serve(l) }()
	tr, err := dialLocal(context.Background(), sock, options{methods: testMethods()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	if err := tr.Call(context.Background(), protocol.MethodHealth, protocol.HealthRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	// The first server goes away with its connection and its socket file.
	_ = first.Close()
	_ = os.Remove(sock)

	other := newLocalServer(t, peerHandler("echo"))
	if err := os.Symlink(other.sock, sock); err != nil {
		t.Fatal(err)
	}
	if err := tr.Call(context.Background(), protocol.MethodHealth, protocol.HealthRequest{}, nil); err == nil {
		t.Fatal("a call through a symbolic link to another socket succeeded")
	}
	if h, _ := other.seen(); len(h) != 0 {
		t.Fatalf("the other socket saw %d requests", len(h))
	}
}
