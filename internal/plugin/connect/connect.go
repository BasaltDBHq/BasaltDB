// Package connect is the ConnectRPC adapter: it reaches a remote plugin at an
// https URL, or a local one on a Unix socket, and gives a plugin.Transport. It speaks the gRPC
// protocol with binary protobuf over HTTP/2, which both a ConnectRPC server
// and a plain gRPC server accept. The messages are the checked-in
// basalt.plugin.v1 service (api/plugin/proto); the host's JSON-shaped params
// and results are carried through their proto3 JSON mapping.
//
// Dial refuses an endpoint before sending any request: plain http, a URL
// with credentials, a query or a fragment, a host and port outside the
// plugin's egress, and a server whose certificate does not verify for the
// URL's host against the system roots. There is no way to turn TLS
// verification off. Redirects are not followed, and no proxy is used: the
// engine connects to the endpoint's host and port and nowhere else.
//
// DialLocal is the local path: the same calls over a Unix socket, HTTP/2
// without TLS, to that socket only (see local.go).
//
// No payload value and no credential is ever written to a log or put in an
// error: a failed call carries a failure class and nothing else.
//
// The Go code under api/plugin/proto is generated from plugin.proto with
// `make proto` (protoc on PATH; the protoc-gen-go and protoc-gen-connect-go
// versions are the ones go.mod requires) and checked in. A test in
// api/plugin checks that it still matches the .proto.
package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	connectrpc "connectrpc.com/connect"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

const (
	connectTimeout      = 10 * time.Second
	keepAlive           = 30 * time.Second
	idleConnTimeout     = 90 * time.Second
	maxResponseHeader   = 64 << 10
	maxIdleConnsPerHost = 4 // the host keeps at most 4 calls open per entry
	// deadlineSlack is how near its deadline a call must be for a
	// DEADLINE_EXCEEDED from the plugin to count as the call's own timeout.
	deadlineSlack = 50 * time.Millisecond
)

var (
	errOtherAddress = errors.New("connect: dial to an address other than the endpoint's")
	errRedirectStop = http.ErrUseLastResponse
)

// options are what tests change; Dial uses the zero value.
type options struct {
	// roots replaces the system roots. Only tests set it, to trust their
	// own test server's certificate; it never relaxes verification.
	roots *x509.CertPool
	// methods adds calls to the platform's table.
	methods map[string]method
	// check, for a local socket, runs on every new connection
	// (DialLocalChecked).
	check func(net.Conn) error
}

// Dial checks a remote endpoint, connects to it once to verify its TLS
// certificate, and returns a transport for it. egress is the manifest's
// network.egress. credentialFile is the entry's auth.credentialFile, or ""
// for none: the engine reads it here, once, and sends its contents as
// "Authorization: Bearer <token>" on every call; the plugin never sees the
// path. A refusal names the endpoint's host or the credential file, and
// wraps one of the Err values of this package (or ctx's error).
func Dial(ctx context.Context, ep plugin.RemoteEndpoint, egress []string, credentialFile string) (plugin.Transport, error) {
	return dial(ctx, ep, egress, credentialFile, options{})
}

func dial(ctx context.Context, ep plugin.RemoteEndpoint, egress []string, credentialFile string, opts options) (plugin.Transport, error) {
	tgt, err := checkEndpoint(ep, egress)
	if err != nil {
		return nil, err
	}
	auth := func(http.Header) {}
	if credentialFile != "" {
		token, err := readCredential(credentialFile)
		if err != nil {
			return nil, err
		}
		bearer := "Bearer " + token
		auth = func(h http.Header) { h.Set("Authorization", bearer) }
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: tgt.host,
		RootCAs:    opts.roots,
	}
	netDialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: keepAlive}
	if err := probe(ctx, tgt, netDialer, tlsConfig); err != nil {
		return nil, err
	}

	tr := &http.Transport{
		// No proxy, whatever the environment says.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != tgt.addr {
				return nil, errOtherAddress
			}
			return netDialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    connectTimeout,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxResponseHeader,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		IdleConnTimeout:        idleConnTimeout,
	}
	return newConn(tr, tgt.baseURL, auth, opts), nil
}

// newConn builds the transport both paths share: gRPC calls through tr to
// baseURL, with the platform's method table, the size caps and the failure
// classes. tr is the only thing that decides where the bytes go.
func newConn(tr *http.Transport, baseURL string, auth func(http.Header), opts options) *conn {
	httpClient := &http.Client{
		Transport: tr,
		// A redirect could lead outside the declared egress: never follow
		// one. The 3xx reaches the call, which fails BAD_RESPONSE.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirectStop },
	}

	table := platformMethods()
	for name, m := range opts.methods {
		table[name] = m
	}
	clients := make(map[string]*call, len(table))
	for name, m := range table {
		clients[name] = &call{
			method: m,
			client: connectrpc.NewClient[wireMessage, wireMessage](httpClient, baseURL+m.procedure,
				connectrpc.WithGRPC(),
				connectrpc.WithCodec(rawCodec{}),
				// No compressed replies: a small gzip body could expand
				// far past the cap before the cap is checked.
				connectrpc.WithAcceptCompression("gzip", nil, nil),
				connectrpc.WithReadMaxBytes(protocol.MaxMessageBytes),
				connectrpc.WithSendMaxBytes(protocol.MaxMessageBytes),
			),
		}
	}

	return &conn{transport: tr, calls: clients, auth: auth, cancels: map[uint64]context.CancelFunc{}}
}

// probe makes one TLS connection to the endpoint and closes it, so a server
// whose certificate does not verify for the host is refused at Dial, before
// any request is sent.
func probe(ctx context.Context, tgt target, netDialer *net.Dialer, tlsConfig *tls.Config) error {
	d := &tls.Dialer{NetDialer: netDialer, Config: tlsConfig.Clone()}
	c, err := d.DialContext(ctx, "tcp", tgt.addr)
	if err == nil {
		_ = c.Close()
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return endpointError(tgt.host, ctxErr)
	}
	var verr *tls.CertificateVerificationError
	var herr x509.HostnameError
	var aerr x509.UnknownAuthorityError
	var cerr x509.CertificateInvalidError
	if errors.As(err, &verr) || errors.As(err, &herr) || errors.As(err, &aerr) || errors.As(err, &cerr) {
		return endpointError(tgt.host, ErrCertificate)
	}
	return endpointError(tgt.host, ErrUnreachable)
}

// call is one method's client.
type call struct {
	method method
	client *connectrpc.Client[wireMessage, wireMessage]
}

// conn is one entry's connection to its remote plugin. It shares nothing
// with any other conn: two entries naming the same URL get separate
// transports, connections and credentials.
type conn struct {
	transport *http.Transport
	calls     map[string]*call
	// auth sets the Authorization header; the token lives only in its
	// closure, never in a field that could be printed.
	auth func(http.Header)

	mu     sync.Mutex
	closed bool
	// cancels ends each call in flight; Close calls them all.
	cancels  map[uint64]context.CancelFunc
	nextCall uint64
	inFlight sync.WaitGroup
	once     sync.Once
}

// Call sends one request and waits for its response. It returns promptly
// when ctx ends, with ctx's own error.
func (c *conn) Call(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cl, ok := c.calls[method]
	if !ok {
		// No mapping for the method: nothing is sent. The plugin is not at
		// fault, so the call fails as a bad exchange, not as UNAVAILABLE.
		return plugin.Fail(plugin.ClassBadResponse)
	}
	body, err := encodeParams(cl.method, params)
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	id, ok := c.enter(cancel)
	if !ok {
		return plugin.Fail(plugin.ClassUnavailable)
	}
	defer c.leave(id)

	var connected, answered atomic.Bool
	callCtx = httptrace.WithClientTrace(callCtx, &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { connected.Store(true) },
		GotFirstResponseByte: func() { answered.Store(true) },
	})

	req := connectrpc.NewRequest(&wireMessage{data: body})
	c.auth(req.Header())
	res, err := cl.client.CallUnary(callCtx, req)
	if err != nil {
		return c.classify(ctx, err, connected.Load() && !answered.Load())
	}
	return decodeResult(cl.method, res.Msg.data, result)
}

// enter registers a call in flight with its cancel, or reports false once
// Close has begun.
func (c *conn) enter(cancel context.CancelFunc) (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, false
	}
	c.nextCall++
	c.cancels[c.nextCall] = cancel
	c.inFlight.Add(1)
	return c.nextCall, true
}

func (c *conn) leave(id uint64) {
	c.mu.Lock()
	delete(c.cancels, id)
	c.mu.Unlock()
	c.inFlight.Done()
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// classify turns a failed call into what the host sees. Nothing of the
// connect error, which may hold the peer's text, is kept. dropped is true
// when a connection was made and then lost before any answer came.
func (c *conn) classify(ctx context.Context, err error, dropped bool) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if c.isClosed() {
		return plugin.Fail(plugin.ClassUnavailable) // closed while in flight
	}
	if dropped {
		// The connection went away while the call was open and nothing came
		// back, so no status of the plugin's own can be in the error. Which
		// connect code the loss maps to (a reset, a closed stream) depends on
		// how the peer died.
		return plugin.Fail(plugin.ClassExited)
	}
	code := connectrpc.CodeOf(err)
	if connectrpc.IsWireError(err) {
		if code == connectrpc.CodeDeadlineExceeded {
			if err := ownDeadline(ctx); err != nil {
				return err
			}
		}
		// The plugin answered with an error status; its message is never read.
		return plugin.Fail(plugin.ClassBadResponse)
	}
	if code == connectrpc.CodeUnavailable {
		// No connection, or an HTTP 503 (or similar) in front of the plugin.
		return plugin.Fail(plugin.ClassUnavailable)
	}
	// Over the size cap, not gRPC, an HTTP error or a redirect.
	return plugin.Fail(plugin.ClassBadResponse)
}

// ownDeadline reports ctx's error when a DEADLINE_EXCEEDED from the plugin
// is the call's own deadline: the plugin applies it (sent as grpc-timeout)
// a hair before our timer fires. It waits at most deadlineSlack past the
// deadline, and only when the deadline is that near; a plugin that answers
// DEADLINE_EXCEEDED early gets nil, so the call fails BAD_RESPONSE at once.
func ownDeadline(ctx context.Context) error {
	dl, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	left := time.Until(dl)
	if left > deadlineSlack {
		return nil
	}
	t := time.NewTimer(left + deadlineSlack)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Close ends every call in flight, waits for them, and closes the
// connections. It is safe to call more than once.
func (c *conn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		for _, cancel := range c.cancels {
			cancel()
		}
		c.mu.Unlock()
		c.inFlight.Wait()
		c.transport.CloseIdleConnections()
	})
	return nil
}
