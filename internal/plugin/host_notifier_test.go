package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

func notifierEntry(agents ...string) Entry {
	e := entry("notify", "default", agents...)
	e.Manifest.Hooks = map[string]protocol.HookDecl{
		string(HookFeedObserve):     {Contract: "feed/1"},
		string(HookApprovalDeliver): {Contract: "deliver/1"},
	}
	return e
}

func batch(seqs ...int64) json.RawMessage {
	parts := make([]string, len(seqs))
	for i, s := range seqs {
		parts[i] = fmt.Sprintf(`{"specversion":"1.0","id":"i:%d","type":"dev.basaltdb.write.applied","data":{"seq":%d}}`, s, s)
	}
	return json.RawMessage("[" + strings.Join(parts, ",") + "]")
}

func answerSeq(seq int64, sent *protocol.FeedObserveRequest) func(string, any, any) error {
	return func(method string, params, result any) error {
		if method != protocol.MethodFeedObserve {
			return errors.New("unexpected method")
		}
		*sent = params.(protocol.FeedObserveRequest)
		result.(*protocol.FeedObserveResponse).LastSeq = seq
		return nil
	}
}

// TestObserveFeedTakesOnlyASeqOfTheBatch: the answer must be the seq of one
// event of the batch; any other is BAD_RESPONSE and moves nothing.
func TestObserveFeedTakesOnlyASeqOfTheBatch(t *testing.T) {
	h := NewHost()
	e := notifierEntry("product_a")
	f := register(t, h, e)
	var sent protocol.FeedObserveRequest

	f.answer = answerSeq(12, &sent)
	got, err := h.ObserveFeed(context.Background(), e.Key, "product_a", batch(10, 12, 15))
	if err != nil || got != 12 {
		t.Fatalf("lastSeq %d, %v", got, err)
	}
	if sent.Agent != "product_a" || string(sent.Events) != string(batch(10, 12, 15)) {
		t.Fatalf("sent %+v", sent)
	}

	for _, bad := range []int64{0, 11, 16, -1} {
		f.answer = answerSeq(bad, &sent)
		_, err := h.ObserveFeed(context.Background(), e.Key, "product_a", batch(10, 12, 15))
		var ce *CallError
		if !errors.As(err, &ce) || ce.Class != ClassBadResponse {
			t.Fatalf("lastSeq %d: %v", bad, err)
		}
	}
}

// TestObserveFeedRefusesABatchBeforeSending: an agent the entry does not
// list, an empty batch, one over 100 events and one that is not a JSON array
// of events with a seq are refused before any byte is sent.
func TestObserveFeedRefusesABatchBeforeSending(t *testing.T) {
	h := NewHost()
	e := notifierEntry("product_a")
	f := register(t, h, e)
	var sent protocol.FeedObserveRequest
	f.answer = answerSeq(1, &sent)
	before := len(f.methods())

	if _, err := h.ObserveFeed(context.Background(), e.Key, "client_x", batch(1)); !errors.Is(err, ErrAgentNotListed) {
		t.Fatalf("unlisted agent: %v", err)
	}
	seqs := make([]int64, protocol.MaxFeedEvents+1)
	for i := range seqs {
		seqs[i] = int64(i + 1)
	}
	for name, events := range map[string]json.RawMessage{
		"empty":    batch(),
		"over 100": batch(seqs...),
		"not JSON": json.RawMessage(`[{`),
		"object":   json.RawMessage(`{"seq":1}`),
		"no seq":   json.RawMessage(`[{"data":{}}]`),
	} {
		if _, err := h.ObserveFeed(context.Background(), e.Key, "product_a", events); err == nil {
			t.Fatalf("%s: sent", name)
		}
	}
	if _, err := h.ObserveFeed(context.Background(), e.Key, "product_a", batch(seqs[:protocol.MaxFeedEvents]...)); err != nil {
		t.Fatalf("100 events: %v", err)
	}
	if got := len(f.methods()) - before; got != 1 {
		t.Fatalf("%d calls reached the plugin, want only the good one", got)
	}
}

// TestDeliverApprovalSendsTheNotice: the notice goes to the plugin as given,
// for a listed agent only.
func TestDeliverApprovalSendsTheNotice(t *testing.T) {
	h := NewHost()
	e := notifierEntry("product_a")
	f := register(t, h, e)
	var sent protocol.ApprovalDeliverRequest
	f.answer = func(method string, params, _ any) error {
		if method != protocol.MethodApprovalDeliver {
			return errors.New("unexpected method")
		}
		sent = params.(protocol.ApprovalDeliverRequest)
		return nil
	}
	notice := json.RawMessage(`{"specversion":"1.0","id":"n","data":{"kind":"APPROVAL_REQUESTED"}}`)
	if err := h.DeliverApproval(context.Background(), e.Key, "product_a", notice); err != nil {
		t.Fatal(err)
	}
	if sent.Agent != "product_a" || string(sent.Event) != string(notice) {
		t.Fatalf("sent %+v", sent)
	}
	if err := h.DeliverApproval(context.Background(), e.Key, "client_x", notice); !errors.Is(err, ErrAgentNotListed) {
		t.Fatalf("unlisted agent: %v", err)
	}
	if err := h.DeliverApproval(context.Background(), e.Key, "product_a", json.RawMessage(`[]`)); err == nil {
		t.Fatal("a notice that is not an object was sent")
	}
}
