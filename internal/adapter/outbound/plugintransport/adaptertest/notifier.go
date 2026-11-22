package adaptertest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// NewNotifier connects to a peer that is a notifier: it answers feed.observe
// with the seq of the batch's last event and approval.deliver with {}. It
// registers its own cleanup with t.
type NewNotifier func(t *testing.T) pluginhost.Transport

// RunNotifier holds a transport to the notifier hooks' rules, whatever the
// wire: both hooks are carried, concurrent calls get their own answers, an
// event of a type or with fields the peer does not know does not break the
// call, and nothing is left running after Close.
func RunNotifier(t *testing.T, newTransport NewNotifier) {
	t.Helper()
	t.Run("TestFeedObserve", func(t *testing.T) { testFeedObserve(t, newTransport) })
	t.Run("TestApprovalDeliver", func(t *testing.T) { testApprovalDeliver(t, newTransport) })
	t.Run("TestUnknownTypeAndFieldsAreCarried", func(t *testing.T) { testUnknownCarried(t, newTransport) })
	t.Run("TestConcurrentHookCallsStayApart", func(t *testing.T) { testHooksConcurrent(t, newTransport) })
	t.Run("TestNoGoroutineLeak", func(t *testing.T) { testHooksNoLeak(t, newTransport) })
}

// FeedEvent is one feed event of type write.applied with the given seq, in
// its JSON form, with a table name that holds characters JSON may escape.
func FeedEvent(seq int64) string {
	return fmt.Sprintf(`{"specversion":"1.0","id":"0193a0f2-5b7e-7c41-9d2a-6e1f00c0ffee:%d",`+
		`"source":"urn:uuid:0193a0f2-5b7e-7c41-9d2a-6e1f00c0ffee","type":"dev.basaltdb.write.applied",`+
		`"time":"2026-11-19T06:02:11Z","subject":"product_a","datacontenttype":"application/json",`+
		`"data":{"installId":"0193a0f2-5b7e-7c41-9d2a-6e1f00c0ffee","seq":%d,"agent":"product_a",`+
		`"changeId":"0193a1b3-0000-7000-8000-000000000001","op":"UPDATE","table":"public.a<b&c>","rows":1,"cascadedRows":0}}`, seq, seq)
}

// Batch is a feed batch of the given events' JSON forms.
func Batch(events ...string) json.RawMessage {
	return json.RawMessage("[" + strings.Join(events, ",") + "]")
}

// Notice is an approval.deliver notice with no link.
const Notice = `{"specversion":"1.0","id":"0193a1b4-0000-7000-8000-000000000001",` +
	`"source":"urn:uuid:0193a0f2-5b7e-7c41-9d2a-6e1f00c0ffee","type":"dev.basaltdb.approval.requested",` +
	`"time":"2026-11-19T06:03:02Z","subject":"product_a","datacontenttype":"application/json",` +
	`"data":{"kind":"APPROVAL_REQUESTED","agent":"product_a","approvalId":"0193a1b3-1111-7000-8000-000000000001",` +
	`"headline":"Update 27 rows in public·leads","expiresAt":"2099-01-01T00:00:00Z",` +
	`"instruction":"Ask the agent for the link to review the held write and approve it with your passkey."}}`

// notifierAgent is the agent every call of the suite names.
const notifierAgent = "product_a"

// Seqs and a spread the suite uses.
const (
	firstSeq    = 5
	secondSeq   = 7
	everyFourth = 4
)

func observe(ctx context.Context, tr pluginhost.Transport, events json.RawMessage) (int64, error) {
	var res pluginproto.FeedObserveResponse
	err := tr.Call(ctx, pluginproto.MethodFeedObserve, pluginproto.FeedObserveRequest{Agent: notifierAgent, Events: events}, &res)
	return res.LastSeq, err
}

func testFeedObserve(t *testing.T, newTransport NewNotifier) {
	tr := newTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt)
	defer cancel()
	got, err := observe(ctx, tr, Batch(FeedEvent(firstSeq), FeedEvent(secondSeq), FeedEvent(1<<53+1)))
	if err != nil {
		t.Fatalf("feed.observe: %v", err)
	}
	if got != 1<<53+1 {
		t.Fatalf("lastSeq = %d, want %d", got, int64(1<<53+1))
	}
}

func testApprovalDeliver(t *testing.T, newTransport NewNotifier) {
	tr := newTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt)
	defer cancel()
	var res map[string]any
	err := tr.Call(ctx, pluginproto.MethodApprovalDeliver,
		pluginproto.ApprovalDeliverRequest{Agent: notifierAgent, Event: json.RawMessage(Notice)}, &res)
	if err != nil {
		t.Fatalf("approval.deliver: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("approval.deliver answered %v, want {}", res)
	}
}

func testUnknownCarried(t *testing.T, newTransport NewNotifier) {
	tr := newTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), waitPrompt)
	defer cancel()
	unknown := `{"specversion":"1.0","id":"x:9","source":"urn:uuid:x","type":"dev.basaltdb.later.thing",` +
		`"subject":"product_a","datacontenttype":"application/json","newattribute":"v",` +
		`"data":{"installId":"x","seq":9,"agent":"product_a","newField":{"a":[1,2]}}}`
	known := strings.Replace(FeedEvent(firstSeq), `"rows":1`, `"rows":1,"laterField":true`, 1)
	got, err := observe(ctx, tr, Batch(known, unknown))
	if err != nil || got != 9 {
		t.Fatalf("lastSeq %d, %v; want 9", got, err)
	}
	notice := strings.Replace(Notice, `"kind":"APPROVAL_REQUESTED"`, `"kind":"APPROVAL_REQUESTED","laterField":1`, 1)
	if err := tr.Call(ctx, pluginproto.MethodApprovalDeliver,
		pluginproto.ApprovalDeliverRequest{Agent: notifierAgent, Event: json.RawMessage(notice)}, nil); err != nil {
		t.Fatalf("approval.deliver with a field the peer does not know: %v", err)
	}
}

func testHooksConcurrent(t *testing.T, newTransport NewNotifier) {
	tr := newTransport(t)
	errs := make(chan error, concCalls)
	var wg sync.WaitGroup
	for i := range concCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
			defer cancel()
			if i%everyFourth == 0 {
				errs <- tr.Call(ctx, pluginproto.MethodApprovalDeliver,
					pluginproto.ApprovalDeliverRequest{Agent: notifierAgent, Event: json.RawMessage(Notice)}, nil)
				return
			}
			seq := int64(i + 1)
			got, err := observe(ctx, tr, Batch(FeedEvent(seq)))
			if err == nil && got != seq {
				err = fmt.Errorf("call for seq %d got lastSeq %d", seq, got)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// testHooksNoLeak runs many hook calls, some cancelled in flight, closes the
// transport and checks that nothing it started is still running.
func testHooksNoLeak(t *testing.T, newTransport NewNotifier) {
	opt := goleak.IgnoreCurrent()
	tr := newTransport(t)
	const calls = 200
	var wg sync.WaitGroup
	for w := range leakWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range calls / leakWorkers {
				n := int64(w*calls/leakWorkers + i + 1)
				ctx, cancel := context.WithTimeout(context.Background(), waitPrompt*2)
				if n%3 == 0 {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Duration(n%spreadMicros)*spreadUnit)
				}
				got, err := observe(ctx, tr, Batch(FeedEvent(n)))
				if err == nil && got != n {
					t.Errorf("call %d got lastSeq %d", n, got)
				}
				if err != nil && ctx.Err() == nil {
					t.Errorf("call %d: %v", n, err)
				}
				cancel()
			}
		}()
	}
	wg.Wait()
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	goleak.VerifyNone(t, opt)
}
