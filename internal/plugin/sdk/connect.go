package sdk

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

const (
	headerTimeout   = 10 * time.Second
	maxHeaderBytes  = 64 << 10
	idleTimeout     = 90 * time.Second
	shutdownTimeout = 2 * time.Second
)

// connectService serves basalt.plugin.v1.PluginService from a server. It embeds
// the generated Unimplemented handler, so a hook's methods added to the
// service later answer "unimplemented" until they are implemented here.
type connectService struct {
	pluginv1connect.UnimplementedPluginServiceHandler
	s *server
}

func (h connectService) Initialize(ctx context.Context, req *connectrpc.Request[pluginv1.InitializeRequest]) (*connectrpc.Response[pluginv1.InitializeResponse], error) {
	in, err := initializeRequestFromProto(req.Msg)
	if err != nil {
		return nil, connectError(errBadParams)
	}
	ctx, cancel := h.s.callContext(ctx)
	defer cancel()
	res, e := h.s.boundedInitialize(ctx, in)
	if e != nil {
		return nil, connectError(e)
	}
	return connectrpc.NewResponse(initializeResponseToProto(res)), nil
}

func (h connectService) Health(ctx context.Context, _ *connectrpc.Request[pluginv1.HealthRequest]) (*connectrpc.Response[pluginv1.HealthResponse], error) {
	ctx, cancel := h.s.callContext(ctx)
	defer cancel()
	return connectrpc.NewResponse(&pluginv1.HealthResponse{Status: h.s.boundedHealth(ctx).Status}), nil
}

func (h connectService) Shutdown(ctx context.Context, _ *connectrpc.Request[pluginv1.ShutdownRequest]) (*connectrpc.Response[pluginv1.ShutdownResponse], error) {
	ctx, cancel := h.s.callContext(ctx)
	defer cancel()
	h.s.boundedShutdown(ctx)
	// Serve stops accepting and finishes this reply before it returns.
	h.s.requestStop()
	return connectrpc.NewResponse(&pluginv1.ShutdownResponse{}), nil
}

func (h connectService) FeedObserve(ctx context.Context, req *connectrpc.Request[pluginv1.FeedObserveRequest]) (*connectrpc.Response[pluginv1.FeedObserveResponse], error) {
	params, ok := hookParams(req.Msg.GetAgent(), "events", req.Msg.GetEvents())
	if !ok {
		return nil, connectError(errBadParams)
	}
	res, e := h.s.connectHook(ctx, protocol.MethodFeedObserve, params)
	if e != nil {
		return nil, connectError(e)
	}
	out, _ := res.(protocol.FeedObserveResponse)
	return connectrpc.NewResponse(&pluginv1.FeedObserveResponse{LastSeq: out.LastSeq}), nil
}

func (h connectService) ApprovalDeliver(ctx context.Context, req *connectrpc.Request[pluginv1.ApprovalDeliverRequest]) (*connectrpc.Response[pluginv1.ApprovalDeliverResponse], error) {
	params, ok := hookParams(req.Msg.GetAgent(), "event", req.Msg.GetEvent())
	if !ok {
		return nil, connectError(errBadParams)
	}
	if _, e := h.s.connectHook(ctx, protocol.MethodApprovalDeliver, params); e != nil {
		return nil, connectError(e)
	}
	return connectrpc.NewResponse(&pluginv1.ApprovalDeliverResponse{}), nil
}

// hookParams builds a hook's JSON-RPC params from its ConnectRPC message
// without encoding the event bytes again, so a plugin's Raw is the bytes
// the engine sent.
func hookParams(agent, field string, events []byte) (json.RawMessage, bool) {
	if !json.Valid(events) {
		return nil, false
	}
	name, err := json.Marshal(agent)
	if err != nil {
		return nil, false
	}
	out := make([]byte, 0, len(events)+len(name)+len(field)+16)
	out = append(out, `{"agent":`...)
	out = append(out, name...)
	out = append(out, `,"`...)
	out = append(out, field...)
	out = append(out, `":`...)
	out = append(out, events...)
	return append(out, '}'), true
}

// connectHook runs one hook call under the server's ConnectRPC slots: at
// most MaxInFlight run at once, a few more wait for a slot until their own
// deadline, and past that a call is answered busy at once. A handler that
// ignores its context keeps its slot until it returns, as over JSON-RPC.
func (s *server) connectHook(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	select {
	case s.connectAdmitted <- struct{}{}:
		defer func() { <-s.connectAdmitted }()
	default:
		return nil, errBusy
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	select {
	case s.connectSlots <- struct{}{}:
		defer func() { <-s.connectSlots }()
	case <-ctx.Done():
		return nil, errDeadline
	}
	return s.dispatch(ctx, method, params)
}

func initializeRequestFromProto(m *pluginv1.InitializeRequest) (protocol.InitializeRequest, error) {
	out := protocol.InitializeRequest{Protocols: m.GetProtocols(), Hooks: m.GetHooks()}
	if l := m.GetLimits(); l != nil {
		out.Limits = protocol.Limits{
			MaxMessageBytes: int(l.GetMaxMessageBytes()),
			MaxInFlight:     int(l.GetMaxInFlight()),
			TimeoutMs:       int(l.GetTimeoutMs()),
		}
	}
	if m.GetConfig() != nil {
		b, err := protojson.Marshal(m.GetConfig())
		if err != nil {
			return out, err
		}
		out.Config = b
	}
	return out, nil
}

func initializeResponseToProto(r protocol.InitializeResponse) *pluginv1.InitializeResponse {
	out := &pluginv1.InitializeResponse{
		Protocol: r.Protocol,
		Name:     r.Name,
		Version:  r.Version,
		Hooks:    make(map[string]*pluginv1.HookDeclaration, len(r.Hooks)),
	}
	for name, d := range r.Hooks {
		out.Hooks[name] = &pluginv1.HookDeclaration{Contract: d.Contract, Roles: d.Roles, EntityTypes: d.EntityTypes}
	}
	if r.Model != nil {
		out.Model = &pluginv1.Model{Name: r.Model.Name, Version: r.Model.Version}
	}
	return out
}

// connectError maps a refusal to a ConnectRPC error carrying the fixed message.
func connectError(e *rpcError) error {
	code := connectrpc.CodeInternal
	switch e.code {
	case codeInvalidParams, codeInvalidRequest, codeParse:
		code = connectrpc.CodeInvalidArgument
	case codeRefused:
		code = connectrpc.CodeFailedPrecondition
	case codeDeadline:
		code = connectrpc.CodeDeadlineExceeded
	case codeBusy:
		code = connectrpc.CodeResourceExhausted
	case codeNoMethod:
		code = connectrpc.CodeUnimplemented
	}
	return connectrpc.NewError(code, errors.New(e.msg))
}

// handler is the HTTP handler of the service, with the size caps in both
// directions and no compression: a small compressed body could expand far past
// the cap before the cap is checked.
func (s *server) connectHandler(token string) http.Handler {
	path, h := pluginv1connect.NewPluginServiceHandler(connectService{s: s},
		connectrpc.WithReadMaxBytes(protocol.MaxMessageBytes),
		connectrpc.WithSendMaxBytes(protocol.MaxMessageBytes),
		connectrpc.WithCompression("gzip", nil, nil),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	if token == "" {
		return mux
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// serveConnect serves ConnectRPC on l until ctx ends. A Unix socket is plain
// h2c (HTTP/1 is accepted too, for tools like curl); any other listener is
// wrapped in TLS with HTTP/2.
func (s *server) serveConnect(ctx context.Context, l net.Listener, tlsConfig *tls.Config, token string) error {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	if _, isUnix := l.Addr().(*net.UnixAddr); isUnix {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		cfg := tlsConfig.Clone()
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
		l = tls.NewListener(l, cfg)
		protocols.SetHTTP2(true)
	}
	srv := &http.Server{
		Handler:           s.connectHandler(token),
		Protocols:         &protocols,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if srv.Shutdown(grace) != nil {
			_ = srv.Close()
		}
	}()
	err := srv.Serve(l)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
