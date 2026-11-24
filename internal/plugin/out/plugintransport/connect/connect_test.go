package connect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/adaptertest"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == peerFlag {
		if len(os.Args) > 3 {
			localPeerMain(os.Args[2], os.Args[3])
		}
		peerMain(os.Args[2])
	}
	os.Exit(m.Run())
}

func remote(url string) pluginmodel.RemoteEndpoint {
	return pluginmodel.RemoteEndpoint{Transport: "connectrpc", URL: url}
}

func TestAdapter(t *testing.T) {
	adaptertest.Run(t, func(t *testing.T, b adaptertest.Behavior) pluginmodel.Transport {
		t.Helper()
		url, addr, roots := startPeer(t, modeOf(b))
		tr, err := dial(context.Background(), remote(url), []string{addr}, "", options{roots: roots, methods: testMethods()})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		return tr
	})
}

// server is an in-process TLS test server that counts what reaches it.
type server struct {
	*httptest.Server
	hits atomic.Int64

	mu      sync.Mutex
	headers []http.Header
	protos  []int
}

func (s *server) addr() string { return strings.TrimPrefix(s.URL, "https://") }

func (s *server) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())
	return p
}

func (s *server) seen() ([]http.Header, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.headers...), append([]int(nil), s.protos...)
}

// newServer starts h behind a recorder, over TLS with HTTP/2. cert, when
// set, replaces httptest's own certificate.
func newServer(t *testing.T, h http.Handler, cert *tls.Certificate) *server {
	t.Helper()
	s := &server{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.headers = append(s.headers, r.Header.Clone())
		s.protos = append(s.protos, r.ProtoMajor)
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	s.EnableHTTP2 = true
	s.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are expected
	if cert != nil {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func dialServer(t *testing.T, s *server, credentialFile string) pluginmodel.Transport {
	t.Helper()
	tr, err := dial(context.Background(), remote(s.URL), []string{s.addr()}, credentialFile, options{roots: s.roots(), methods: testMethods()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func classOf(err error) pluginmodel.FailureClass {
	var c pluginmodel.Classed
	if errors.As(err, &c) {
		return c.FailureClass()
	}
	return ""
}

type echoPayload struct {
	N int    `json:"n"`
	S string `json:"s"`
}

func TestRemoteRefusesPlainHTTP(t *testing.T) {
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(ts.Close)
	addr := strings.TrimPrefix(ts.URL, "http://")
	host, _, _ := net.SplitHostPort(addr)

	for _, url := range []string{ts.URL, "http://user:hunter2@" + addr + "/p?q=1"} {
		_, err := dial(context.Background(), remote(url), []string{addr}, "", options{methods: testMethods()})
		if !errors.Is(err, ErrPlainHTTP) {
			t.Fatalf("%s: err = %v, want ErrPlainHTTP", url, err)
		}
		if msg := err.Error(); !strings.Contains(msg, host) || strings.Contains(msg, addr) || strings.Contains(msg, "hunter2") || strings.Contains(msg, "q=1") {
			t.Fatalf("the error must name the host and nothing else of the URL: %q", msg)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}
}

func TestRemoteRefusesBadURLs(t *testing.T) {
	for _, url := range []string{
		"https://user:hunter2@127.0.0.1:8443",
		"https://127.0.0.1:8443/?token=hunter2",
		"https://127.0.0.1:8443/#hunter2",
		"ftp://127.0.0.1:8443",
		"https://:8443",
		"https://127.0.0.1:0",
		"%zz",
	} {
		_, err := Dial(context.Background(), remote(url), []string{"127.0.0.1:8443"}, "")
		if !errors.Is(err, ErrEndpointURL) {
			t.Fatalf("%s: err = %v, want ErrEndpointURL", url, err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("the error carries part of the URL: %v", err)
		}
	}
	_, err := Dial(context.Background(), pluginmodel.RemoteEndpoint{Transport: "jsonrpc-unix", URL: "https://127.0.0.1:8443"}, []string{"127.0.0.1:8443"}, "")
	if !errors.Is(err, ErrEndpointURL) {
		t.Fatalf("another transport: %v", err)
	}
}

// certFor makes a self-signed certificate valid for dnsName (and ips),
// which is its own root.
func certFor(t *testing.T, dnsName string, ips ...net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		IPAddresses:           ips,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestRemoteRefusesWrongHost(t *testing.T) {
	// Control: a certificate from the same maker, valid for the loopback
	// address and trusted, is accepted. Only the name differs below.
	good, goodRoots := certFor(t, "other.test", net.IPv4(127, 0, 0, 1))
	ok := newServer(t, peerHandler("echo"), &good)
	tr, err := dial(context.Background(), remote(ok.URL), []string{ok.addr()}, "", options{roots: goodRoots})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	_ = tr.Close()

	// A trusted certificate valid for other.test only, served at 127.0.0.1.
	other, roots := certFor(t, "other.test")
	s := newServer(t, peerHandler("echo"), &other)
	_, err = dial(context.Background(), remote(s.URL), []string{s.addr()}, "", options{roots: roots})
	if !errors.Is(err, ErrCertificate) {
		t.Fatalf("err = %v, want ErrCertificate", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error must name the endpoint's host: %v", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}

	// The system roots do not trust httptest's certificate: Dial (the
	// production entry) refuses it.
	plain := newServer(t, peerHandler("echo"), nil)
	if _, err := Dial(context.Background(), remote(plain.URL), []string{plain.addr()}, ""); !errors.Is(err, ErrCertificate) {
		t.Fatalf("an untrusted certificate: %v", err)
	}
	if n := plain.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}
}

func TestRemoteHostMustBeInEgress(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	host, port, _ := net.SplitHostPort(s.addr())
	for _, egress := range [][]string{
		nil,
		{host},
		{host + ":1"},
		{"localhost:" + port},
		{"127.0.0.2:" + port},
	} {
		_, err := dial(context.Background(), remote(s.URL), egress, "", options{roots: s.roots()})
		if !errors.Is(err, ErrNotInEgress) {
			t.Fatalf("egress %v: err = %v, want ErrNotInEgress", egress, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}

	// A URL with no port is port 443; case is ignored.
	for _, c := range []struct {
		url    string
		egress []string
		ok     bool
	}{
		{"https://ner.acme.example", []string{"ner.acme.example:443"}, true},
		{"https://NER.acme.example/v1/", []string{"ner.acme.example:443"}, true},
		{"https://ner.acme.example", []string{"ner.acme.example"}, false},
		{"https://ner.acme.example:8443", []string{"ner.acme.example:443"}, false},
		{"https://[::1]:8443", []string{"[::1]:8443"}, true},
	} {
		tgt, err := checkEndpoint(remote(c.url), c.egress)
		if (err == nil) != c.ok {
			t.Fatalf("%s in %v: err = %v", c.url, c.egress, err)
		}
		if c.ok && !strings.HasPrefix(tgt.baseURL, "https://"+c.egress[0]) {
			t.Fatalf("%s: base URL %s", c.url, tgt.baseURL)
		}
	}
}

// writeToken writes a token file as the tests' credential.
func writeToken(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// captureLogs sends the standard logger (and so slog's default handler,
// which writes through it) to a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

func TestBearerFromCredentialFile(t *testing.T) {
	const token = "tok-7f3a9c2e-test-only"
	logs := captureLogs(t)
	s := newServer(t, peerHandler("echo"), nil)
	path := writeToken(t, token+"\n", 0o600)
	tr := dialServer(t, s, path)

	var out echoPayload
	if err := tr.Call(context.Background(), echoMethod, echoPayload{N: 1, S: "a"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := tr.Call(context.Background(), pluginproto.MethodHealth, pluginproto.HealthRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	headers, _ := s.seen()
	if len(headers) != 2 {
		t.Fatalf("the server saw %d requests", len(headers))
	}
	for _, h := range headers {
		if got := h.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
		for k, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, path) || strings.Contains(v, filepath.Base(path)) {
					t.Fatalf("header %s carries the credential file's path", k)
				}
			}
		}
	}

	// Failures carry no token either: a plugin error, and refused files.
	errSrv := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectrpc.NewErrorWriter().Write(w, r, connectrpc.NewError(connectrpc.CodePermissionDenied, errors.New("bad Bearer "+token)))
	}), nil)
	errs := make([]error, 0, 5)
	errs = append(errs, dialServer(t, errSrv, path).Call(context.Background(), echoMethod, echoPayload{}, &out))
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		_, err := dial(context.Background(), remote(s.URL), []string{s.addr()}, writeToken(t, token, mode), options{roots: s.roots()})
		errs = append(errs, err)
	}
	_, err := dial(context.Background(), remote(s.URL), []string{s.addr()}, writeToken(t, token+" x", 0o600), options{roots: s.roots()})
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("a call or dial that must fail succeeded")
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("an error carries the token: %v", err)
		}
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("a log line carries the token")
	}
}

func TestCredentialFileRules(t *testing.T) {
	const token = "zqx-rules-test-only"
	s := newServer(t, peerHandler("echo"), nil)
	dir := t.TempDir()
	good := writeToken(t, token, 0o600)
	link := filepath.Join(dir, "link.token")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing":       filepath.Join(dir, "none.token"),
		"relative":      "plugin.token",
		"a directory":   dir,
		"a symlink":     link,
		"group-read":    writeToken(t, token, 0o640),
		"world-read":    writeToken(t, token, 0o604),
		"empty":         writeToken(t, "", 0o600),
		"only newline":  writeToken(t, "\n", 0o600),
		"two lines":     writeToken(t, token+"\n"+token+"\n", 0o600),
		"a space":       writeToken(t, "zqx en", 0o600),
		"a CR inside":   writeToken(t, "zqx\ren", 0o600),
		"too large":     writeToken(t, strings.Repeat("a", maxCredentialBytes+1), 0o600),
		"non-ASCII":     writeToken(t, "zqxö", 0o600),
		"two newlines":  writeToken(t, token+"\n\n", 0o600),
		"trailing tab":  writeToken(t, token+"\t", 0o600),
		"leading space": writeToken(t, " "+token, 0o600),
	}
	for name, path := range cases {
		_, err := dial(context.Background(), remote(s.URL), []string{s.addr()}, path, options{roots: s.roots()})
		if !errors.Is(err, ErrCredentialFile) {
			t.Fatalf("%s: err = %v, want ErrCredentialFile", name, err)
		}
		if strings.Contains(err.Error(), "zqx") || strings.Contains(err.Error(), "aaaa") {
			t.Fatalf("%s: the error carries the contents: %v", name, err)
		}
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}

	// One trailing LF or CRLF is dropped; mode 0400 is fine.
	for _, contents := range []string{token, token + "\n", token + "\r\n"} {
		tr := dialServer(t, s, writeToken(t, contents, 0o400))
		if err := tr.Call(context.Background(), pluginproto.MethodHealth, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	headers, _ := s.seen()
	for _, h := range headers {
		if h.Get("Authorization") != "Bearer "+token {
			t.Fatalf("Authorization = %q", h.Get("Authorization"))
		}
	}
}

func TestSpeaksGRPC(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	tr := dialServer(t, s, "")
	var got pluginproto.HealthResponse
	if err := tr.Call(context.Background(), pluginproto.MethodHealth, pluginproto.HealthRequest{}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "READY" {
		t.Fatalf("status = %q", got.Status)
	}

	// The stock gRPC client reaches the same handler.
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: s.roots(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	t.Cleanup(hc.CloseIdleConnections)
	stock := pluginv1connect.NewPluginServiceClient(hc, s.URL, connectrpc.WithGRPC())
	res, err := stock.Health(context.Background(), connectrpc.NewRequest(&pluginv1.HealthRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetStatus() != "READY" {
		t.Fatalf("stock client status = %q", res.Msg.GetStatus())
	}

	// Both arrived as gRPC with binary protobuf over HTTP/2: what a plain
	// gRPC server accepts.
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

func TestInitializeRoundTrip(t *testing.T) {
	var gotReq atomic.Pointer[pluginv1.InitializeRequest]
	path, h := pluginv1connect.NewPluginServiceHandler(initService{got: &gotReq})
	mux := http.NewServeMux()
	mux.Handle(path, h)
	s := newServer(t, mux, nil)
	tr := dialServer(t, s, "")

	req := pluginproto.InitializeRequest{
		Protocols: []string{"basalt-plugin/1"},
		Hooks:     []string{"wire.detect"},
		Config:    pluginproto.RawObject(`{"languages":["en","id"]}`),
		Limits:    pluginproto.Limits{MaxMessageBytes: pluginproto.MaxMessageBytes, MaxInFlight: 4, TimeoutMs: 2000},
	}
	var res pluginproto.InitializeResponse
	if err := tr.Call(context.Background(), pluginproto.MethodInitialize, req, &res); err != nil {
		t.Fatal(err)
	}
	in := gotReq.Load()
	if in.GetLimits().GetMaxMessageBytes() != pluginproto.MaxMessageBytes || in.GetLimits().GetTimeoutMs() != 2000 ||
		len(in.GetConfig().GetFields()["languages"].GetListValue().GetValues()) != 2 || in.GetHooks()[0] != "wire.detect" {
		t.Fatalf("the plugin got %v", in)
	}
	if res.Protocol != "basalt-plugin/1" || res.Name != "acme-ner" || res.Hooks["wire.detect"].EntityTypes[0] != "PERSON_NAME" ||
		res.Model == nil || res.Model.Name != "ner" {
		t.Fatalf("the engine got %+v", res)
	}
}

type initService struct {
	pluginv1connect.UnimplementedPluginServiceHandler
	got *atomic.Pointer[pluginv1.InitializeRequest]
}

func (s initService) Initialize(_ context.Context, req *connectrpc.Request[pluginv1.InitializeRequest]) (*connectrpc.Response[pluginv1.InitializeResponse], error) {
	s.got.Store(req.Msg)
	return connectrpc.NewResponse(&pluginv1.InitializeResponse{
		Protocol: "basalt-plugin/1", Name: "acme-ner", Version: "1.0.0",
		Hooks: map[string]*pluginv1.HookDeclaration{"wire.detect": {Contract: "detector/1", Roles: []string{"VALUE"}, EntityTypes: []string{"PERSON_NAME"}}},
		Model: &pluginv1.Model{Name: "ner", Version: "1"},
	}), nil
}

func TestRedirectIsNotFollowed(t *testing.T) {
	target := newServer(t, peerHandler("echo"), nil)
	s := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}), nil)
	// Both hosts are in egress, so only the redirect rule stops it.
	tr, err := dial(context.Background(), remote(s.URL), []string{s.addr(), target.addr()}, "", options{roots: s.roots(), methods: testMethods()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	err = tr.Call(context.Background(), echoMethod, echoPayload{N: 1}, nil)
	if classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("err = %v, want BAD_RESPONSE", err)
	}
	if n := target.hits.Load(); n != 0 {
		t.Fatalf("the redirect was followed: %d requests", n)
	}
}

func TestNoProxy(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	tr := dialServer(t, s, "")
	if tr.(*conn).transport.Proxy != nil {
		t.Fatal("the transport uses a proxy")
	}
}

func TestPluginErrorCarriesNoText(t *testing.T) {
	s := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectrpc.NewErrorWriter().Write(w, r, connectrpc.NewError(connectrpc.CodeInternal, errors.New(adaptertest.GarbageMarker)))
	}), nil)
	tr := dialServer(t, s, "")
	err := tr.Call(context.Background(), echoMethod, echoPayload{N: 1}, nil)
	if classOf(err) != pluginmodel.ClassBadResponse || strings.Contains(err.Error(), adaptertest.GarbageMarker) {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestOverTheCapIsNotSent(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	tr := dialServer(t, s, "")
	err := tr.Call(context.Background(), echoMethod, echoPayload{S: strings.Repeat("x", pluginproto.MaxMessageBytes)}, nil)
	if classOf(err) != pluginmodel.ClassOverLimit {
		t.Fatalf("err = %v, want OVER_LIMIT", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}
}

func TestUnknownMethodIsNotSent(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	tr := dialServer(t, s, "")
	if err := tr.Call(context.Background(), "wire.verdict", map[string]any{}, nil); classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("an unmapped method: %v, want BAD_RESPONSE", err)
	}
	// Params that do not fit the message (a string for an int32) are not sent.
	bad := map[string]any{"limits": map[string]any{"timeoutMs": "soon"}}
	if err := tr.Call(context.Background(), pluginproto.MethodInitialize, bad, nil); classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("params of the wrong shape: %v, want BAD_RESPONSE", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Fatalf("the server got %d requests", n)
	}
}

func TestUnreachableEndpoint(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, err = dial(context.Background(), remote("https://"+addr), []string{addr}, "", options{})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestInstancesShareNothing(t *testing.T) {
	s := newServer(t, peerHandler("echo"), nil)
	a := writeToken(t, "token-a", 0o600)
	b := writeToken(t, "token-b", 0o600)
	ta := dialServer(t, s, a)
	tb := dialServer(t, s, b)
	if err := ta.Call(context.Background(), pluginproto.MethodHealth, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = ta.Close()
	if err := tb.Call(context.Background(), pluginproto.MethodHealth, nil, nil); err != nil {
		t.Fatalf("closing one entry broke the other: %v", err)
	}
	headers, _ := s.seen()
	if headers[0].Get("Authorization") != "Bearer token-a" || headers[1].Get("Authorization") != "Bearer token-b" {
		t.Fatal("the entries' credentials mixed")
	}
}

// rawFrame answers every call with one gRPC frame: flags, then a length
// prefix of declared bytes, then body.
func rawFrame(flags byte, declared uint32, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		frame := make([]byte, 5, 5+len(body))
		frame[0] = flags
		binary.BigEndian.PutUint32(frame[1:], declared)
		frame = append(frame, body...)
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Set("Grpc-Encoding", "gzip")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frame)
		w.Header().Set("Grpc-Status", "0")
	})
}

func TestReplyOverTheCapIsRefused(t *testing.T) {
	// A length prefix over the cap, with no body behind it.
	big := newServer(t, rawFrame(0, pluginproto.MaxMessageBytes+1, nil), nil)
	err := dialServer(t, big, "").Call(context.Background(), pluginproto.MethodHealth, nil, nil)
	if classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("over-cap prefix: %v", err)
	}

	// A small gzip body that inflates past the cap: compressed replies are
	// not accepted at all.
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write(make([]byte, pluginproto.MaxMessageBytes+1024))
	_ = zw.Close()
	bomb := newServer(t, rawFrame(1, uint32(zb.Len()), zb.Bytes()), nil)
	err = dialServer(t, bomb, "").Call(context.Background(), pluginproto.MethodHealth, nil, nil)
	if classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("gzip reply: %v", err)
	}
	headers, _ := bomb.seen()
	if ae := headers[0].Get("Grpc-Accept-Encoding"); strings.Contains(ae, "gzip") {
		t.Fatalf("the adapter offers gzip: %q", ae)
	}
}

func TestEarlyDeadlineFromPluginIsNotWaitedOn(t *testing.T) {
	s := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectrpc.NewErrorWriter().Write(w, r, connectrpc.NewError(connectrpc.CodeDeadlineExceeded, errors.New("late")))
	}), nil)
	tr := dialServer(t, s, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	err := tr.Call(ctx, pluginproto.MethodHealth, nil, nil)
	if classOf(err) != pluginmodel.ClassBadResponse {
		t.Fatalf("err = %v, want BAD_RESPONSE", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the call waited %v for a deadline the plugin claimed", took)
	}
	closed := make(chan struct{})
	go func() { _ = tr.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close hangs")
	}
}

// TestHTTPStatusClasses pins what an HTTP error in front of the plugin
// gives: a refused token (401) and a gateway with no plugin behind it (503).
func TestHTTPStatusClasses(t *testing.T) {
	for status, want := range map[int]pluginmodel.FailureClass{
		http.StatusUnauthorized:       pluginmodel.ClassBadResponse,
		http.StatusServiceUnavailable: pluginmodel.ClassUnavailable,
	} {
		s := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}), nil)
		err := dialServer(t, s, "").Call(context.Background(), pluginproto.MethodHealth, nil, nil)
		if got := classOf(err); got != want {
			t.Fatalf("HTTP %d: class %q (%v), want %q", status, got, err, want)
		}
	}
}
