package connect

import (
	"encoding/json"
	"errors"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// method maps one protocol method (the JSON-RPC name the host calls) to its
// ConnectRPC procedure and messages. Each hook's contract adds its methods
// here when it adds its messages to plugin.proto.
type method struct {
	procedure   string
	newRequest  func() proto.Message
	newResponse func() proto.Message
	// fromJSON, when set, fills the request from the params' JSON form in
	// place of proto3 JSON: the notifier hooks carry their events as bytes
	// that hold the events' own JSON, which proto3 JSON would want as
	// base64.
	fromJSON func(js []byte, msg proto.Message) error
	// toJSON, when set, renders the reply as the params' JSON form in place
	// of proto3 JSON, which writes a 64-bit integer as a string.
	toJSON func(msg proto.Message) ([]byte, error)
}

func platformMethods() map[string]method {
	return map[string]method{
		pluginproto.MethodInitialize: {
			procedure:   pluginv1connect.PluginServiceInitializeProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.InitializeRequest) },
			newResponse: func() proto.Message { return new(pluginv1.InitializeResponse) },
		},
		pluginproto.MethodHealth: {
			procedure:   pluginv1connect.PluginServiceHealthProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.HealthRequest) },
			newResponse: func() proto.Message { return new(pluginv1.HealthResponse) },
		},
		pluginproto.MethodShutdown: {
			procedure:   pluginv1connect.PluginServiceShutdownProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.ShutdownRequest) },
			newResponse: func() proto.Message { return new(pluginv1.ShutdownResponse) },
		},
		pluginproto.MethodFeedObserve: {
			procedure:   pluginv1connect.PluginServiceFeedObserveProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.FeedObserveRequest) },
			newResponse: func() proto.Message { return new(pluginv1.FeedObserveResponse) },
			fromJSON: func(js []byte, msg proto.Message) error {
				var in pluginproto.FeedObserveRequest
				if err := json.Unmarshal(js, &in); err != nil {
					return err
				}
				m, _ := msg.(*pluginv1.FeedObserveRequest)
				m.Agent, m.Events = in.Agent, in.Events
				return nil
			},
			toJSON: func(msg proto.Message) ([]byte, error) {
				m, _ := msg.(*pluginv1.FeedObserveResponse)
				return json.Marshal(pluginproto.FeedObserveResponse{LastSeq: m.GetLastSeq()})
			},
		},
		pluginproto.MethodApprovalDeliver: {
			procedure:   pluginv1connect.PluginServiceApprovalDeliverProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.ApprovalDeliverRequest) },
			newResponse: func() proto.Message { return new(pluginv1.ApprovalDeliverResponse) },
			fromJSON: func(js []byte, msg proto.Message) error {
				var in pluginproto.ApprovalDeliverRequest
				if err := json.Unmarshal(js, &in); err != nil {
					return err
				}
				m, _ := msg.(*pluginv1.ApprovalDeliverRequest)
				m.Agent, m.Event = in.Agent, in.Event
				return nil
			},
		},
	}
}

var (
	// The params' JSON names are the proto3 JSON names (CONTRACT.md,
	// Plugins, Transports); a field the message lacks is dropped.
	jsonToProto = protojson.UnmarshalOptions{DiscardUnknown: true}
	protoToJSON = protojson.MarshalOptions{}
)

// encodeParams turns the host's params into the method's binary message.
// Params over the size cap fail OVER_LIMIT, and params that do not fit the
// message fail BAD_RESPONSE (as the JSON-RPC adapter's do); neither is sent.
func encodeParams(m method, params any) ([]byte, error) {
	msg := m.newRequest()
	if params != nil {
		js, err := pluginproto.Marshal(params)
		if err != nil {
			return nil, pluginmodel.Fail(pluginmodel.ClassBadResponse)
		}
		if len(js) > pluginproto.MaxMessageBytes {
			return nil, pluginmodel.Fail(pluginmodel.ClassOverLimit)
		}
		fill := jsonToProto.Unmarshal
		if m.fromJSON != nil {
			fill = m.fromJSON
		}
		if err := fill(js, msg); err != nil {
			return nil, pluginmodel.Fail(pluginmodel.ClassBadResponse)
		}
	}
	body, err := proto.Marshal(msg)
	if err != nil {
		return nil, pluginmodel.Fail(pluginmodel.ClassBadResponse)
	}
	if len(body) > pluginproto.MaxMessageBytes {
		return nil, pluginmodel.Fail(pluginmodel.ClassOverLimit)
	}
	return body, nil
}

// decodeResult checks the reply is the method's message and, when result is
// not nil, fills it through the message's proto3 JSON form.
func decodeResult(m method, body []byte, result any) error {
	msg := m.newResponse()
	if err := proto.Unmarshal(body, msg); err != nil {
		return pluginmodel.Fail(pluginmodel.ClassBadResponse)
	}
	if result == nil {
		return nil
	}
	render := protoToJSON.Marshal
	if m.toJSON != nil {
		render = m.toJSON
	}
	js, err := render(msg)
	if err != nil {
		return pluginmodel.Fail(pluginmodel.ClassBadResponse)
	}
	if err := json.Unmarshal(js, result); err != nil {
		return pluginmodel.Fail(pluginmodel.ClassBadResponse)
	}
	return nil
}

// wireMessage is a message already in its binary form. The adapter does its
// own proto encoding, so it can check sizes and keep decode errors (which
// may quote the peer's bytes) out of every error it returns.
type wireMessage struct{ data []byte }

// rawCodec is connect's "proto" codec over wireMessage: bytes pass through
// unchanged, so the content type on the wire is application/grpc+proto.
type rawCodec struct{}

var errNotWireMessage = errors.New("connect: codec given a value that is not a wire message")

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(*wireMessage)
	if !ok {
		return nil, errNotWireMessage
	}
	return m.data, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(*wireMessage)
	if !ok {
		return errNotWireMessage
	}
	m.data = append([]byte(nil), data...) // connect reuses data's buffer
	return nil
}
