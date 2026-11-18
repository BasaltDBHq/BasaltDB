package connect

import (
	"encoding/json"
	"errors"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// method maps one protocol method (the JSON-RPC name the host calls) to its
// ConnectRPC procedure and messages. Each hook's contract adds its methods
// here when it adds its messages to plugin.proto.
type method struct {
	procedure   string
	newRequest  func() proto.Message
	newResponse func() proto.Message
}

func platformMethods() map[string]method {
	return map[string]method{
		protocol.MethodInitialize: {
			procedure:   pluginv1connect.PluginServiceInitializeProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.InitializeRequest) },
			newResponse: func() proto.Message { return new(pluginv1.InitializeResponse) },
		},
		protocol.MethodHealth: {
			procedure:   pluginv1connect.PluginServiceHealthProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.HealthRequest) },
			newResponse: func() proto.Message { return new(pluginv1.HealthResponse) },
		},
		protocol.MethodShutdown: {
			procedure:   pluginv1connect.PluginServiceShutdownProcedure,
			newRequest:  func() proto.Message { return new(pluginv1.ShutdownRequest) },
			newResponse: func() proto.Message { return new(pluginv1.ShutdownResponse) },
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
		js, err := json.Marshal(params)
		if err != nil {
			return nil, plugin.Fail(plugin.ClassBadResponse)
		}
		if len(js) > protocol.MaxMessageBytes {
			return nil, plugin.Fail(plugin.ClassOverLimit)
		}
		if err := jsonToProto.Unmarshal(js, msg); err != nil {
			return nil, plugin.Fail(plugin.ClassBadResponse)
		}
	}
	body, err := proto.Marshal(msg)
	if err != nil {
		return nil, plugin.Fail(plugin.ClassBadResponse)
	}
	if len(body) > protocol.MaxMessageBytes {
		return nil, plugin.Fail(plugin.ClassOverLimit)
	}
	return body, nil
}

// decodeResult checks the reply is the method's message and, when result is
// not nil, fills it through the message's proto3 JSON form.
func decodeResult(m method, body []byte, result any) error {
	msg := m.newResponse()
	if err := proto.Unmarshal(body, msg); err != nil {
		return plugin.Fail(plugin.ClassBadResponse)
	}
	if result == nil {
		return nil
	}
	js, err := protoToJSON.Marshal(msg)
	if err != nil {
		return plugin.Fail(plugin.ClassBadResponse)
	}
	if err := json.Unmarshal(js, result); err != nil {
		return plugin.Fail(plugin.ClassBadResponse)
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
