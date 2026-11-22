package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	connectrpc "connectrpc.com/connect"

	pluginv1 "github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1"
	"github.com/basaltdbhq/basaltdb/api/plugin/proto/basalt/plugin/v1/pluginv1connect"
	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// notifierService answers the two notifier hooks and keeps what it got.
type notifierService struct {
	pluginv1connect.UnimplementedPluginServiceHandler
	feed    *atomic.Pointer[pluginv1.FeedObserveRequest]
	deliver *atomic.Pointer[pluginv1.ApprovalDeliverRequest]
	lastSeq int64
}

func (s notifierService) FeedObserve(_ context.Context, req *connectrpc.Request[pluginv1.FeedObserveRequest]) (*connectrpc.Response[pluginv1.FeedObserveResponse], error) {
	s.feed.Store(req.Msg)
	return connectrpc.NewResponse(&pluginv1.FeedObserveResponse{LastSeq: s.lastSeq}), nil
}

func (s notifierService) ApprovalDeliver(_ context.Context, req *connectrpc.Request[pluginv1.ApprovalDeliverRequest]) (*connectrpc.Response[pluginv1.ApprovalDeliverResponse], error) {
	s.deliver.Store(req.Msg)
	return connectrpc.NewResponse(&pluginv1.ApprovalDeliverResponse{}), nil
}

// TestNotifierHooksCarryTheEventBytes: over ConnectRPC the batch and the
// notice travel as their exact JSON bytes, not as a protobuf rendering of
// them, and a 64-bit lastSeq comes back as a number.
func TestNotifierHooksCarryTheEventBytes(t *testing.T) {
	svc := notifierService{
		feed:    &atomic.Pointer[pluginv1.FeedObserveRequest]{},
		deliver: &atomic.Pointer[pluginv1.ApprovalDeliverRequest]{},
		lastSeq: 1<<53 + 1, // past what a float64 holds exactly
	}
	path, h := pluginv1connect.NewPluginServiceHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	tr := dialServer(t, newServer(t, mux, nil), "")

	events := json.RawMessage(`[{"specversion":"1.0","id":"x:9007199254740993","type":"dev.basaltdb.write.applied","data":{"seq":9007199254740993,"table":"a<b"}}]`)
	var res protocol.FeedObserveResponse
	if err := tr.Call(context.Background(), protocol.MethodFeedObserve, protocol.FeedObserveRequest{Agent: "product_a", Events: events}, &res); err != nil {
		t.Fatal(err)
	}
	got := svc.feed.Load()
	if got.GetAgent() != "product_a" || string(got.GetEvents()) != string(events) {
		t.Fatalf("the plugin got %q %q", got.GetAgent(), got.GetEvents())
	}
	if res.LastSeq != 1<<53+1 {
		t.Fatalf("lastSeq = %d", res.LastSeq)
	}

	// Any result type that has the JSON field works, as for every method.
	var loose map[string]json.Number
	if err := tr.Call(context.Background(), protocol.MethodFeedObserve, &protocol.FeedObserveRequest{Agent: "product_a", Events: events}, &loose); err != nil {
		t.Fatal(err)
	}
	if loose["lastSeq"] != "9007199254740993" {
		t.Fatalf("lastSeq as JSON = %v", loose)
	}

	notice := json.RawMessage(`{"specversion":"1.0","id":"n","type":"dev.basaltdb.approval.requested","data":{"kind":"APPROVAL_REQUESTED"}}`)
	if err := tr.Call(context.Background(), protocol.MethodApprovalDeliver, protocol.ApprovalDeliverRequest{Agent: "product_a", Event: notice}, &protocol.ApprovalDeliverResponse{}); err != nil {
		t.Fatal(err)
	}
	if d := svc.deliver.Load(); d.GetAgent() != "product_a" || string(d.GetEvent()) != string(notice) {
		t.Fatalf("the plugin got %q %q", d.GetAgent(), d.GetEvent())
	}
}

// TestNotifierParamsThatAreNotJSONAreNotSent: event bytes that are not JSON
// never reach the plugin.
func TestNotifierParamsThatAreNotJSONAreNotSent(t *testing.T) {
	s := newServer(t, http.NotFoundHandler(), nil)
	tr := dialServer(t, s, "")
	before := s.hits.Load()
	err := tr.Call(context.Background(), protocol.MethodFeedObserve, protocol.FeedObserveRequest{Agent: "a", Events: json.RawMessage(`[{`)}, nil)
	if err == nil {
		t.Fatal("sent")
	}
	err = tr.Call(context.Background(), protocol.MethodApprovalDeliver, protocol.ApprovalDeliverRequest{Agent: "a", Event: json.RawMessage(`nope`)}, nil)
	if err == nil {
		t.Fatal("sent")
	}
	if s.hits.Load() != before {
		t.Fatal("bytes reached the plugin")
	}
}
