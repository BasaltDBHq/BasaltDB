//go:build linux || darwin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin/testnotifier"
)

// notifierBin is the test notifier, built once for the tests that use it.
var notifierBin = struct {
	dir  string
	path string
	err  error
	done bool
}{}

func buildNotifier(t *testing.T) string {
	t.Helper()
	// Tests that share it build it before they run in parallel.
	if !notifierBin.done {
		notifierBin.dir, notifierBin.err = os.MkdirTemp("", "bnotifier")
		if notifierBin.err == nil {
			notifierBin.path, notifierBin.err = testnotifier.Build(notifierBin.dir)
		}
		notifierBin.done = true
	}
	require.NoError(t, notifierBin.err)
	return notifierBin.path
}

// notifierEngine is a live engine whose agent product_a has the test
// notifier installed through the approval flow and running: a real plugin
// built from the SDK that serves feed.observe and approval.deliver and
// keeps every call it gets.
type notifierEngine struct {
	*liveEngine
	record  string
	control string
}

// newNotifierEngine starts the engine and installs the notifier as the
// agent does: basalt plugin add, the person's passkey, basalt plugin
// approve. It returns once the plugin serves the agent.
func newNotifierEngine(t *testing.T, bin string, o testnotifier.Options) *notifierEngine {
	t.Helper()
	e := &notifierEngine{liveEngine: newLiveEngine(t)}
	base := filepath.Dir(e.src)
	e.record, e.control = filepath.Join(base, "received.jsonl"), filepath.Join(base, "mode")
	o.Record, o.Control = e.record, e.control
	src := filepath.Join(base, "notifier")
	require.NoError(t, testnotifier.WriteDir(src, bin, o))
	e.start()

	r := e.agent("add", src, "--agents", "product_a", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	res := approvalResultOf(t, r)
	require.Len(t, res.Approvals, 1)
	r = e.agent("approve", e.sign(res.Approvals[0].URL))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Eventually(t, func() bool { return len(e.pluginProblems()) == 0 }, 30*time.Second, 100*time.Millisecond,
		"the notifier serves the agent")
	// The feed's cursor starts at the ledger's head at its first read, a
	// moment after the plugin is ready. Small writes until one arrives as
	// a feed event: from then on the plugin takes calls and nothing the
	// test does is before the cursor.
	require.Eventually(t, func() bool {
		body, isError := e.tool("write", map[string]any{"sql": "UPDATE public.leads SET score = score + 1 WHERE id = 2", "intent": "warm up"})
		require.False(t, isError, "%v", body)
		_, types, _ := e.records()
		return len(types) > 0
	}, 90*time.Second, time.Second, "the feed follows the agent")
	return e
}

// tool calls one of the agent's MCP tools on the engine's socket, as the
// agent's client does, and returns the result's body and whether it is an
// error.
func (e *liveEngine) tool(name string, args map[string]any) (map[string]any, bool) {
	e.t.Helper()
	conn, err := net.Dial("unix", config.SocketPath(e.socketDir, "product_a"))
	require.NoError(e.t, err)
	defer conn.Close()
	require.NoError(e.t, conn.SetDeadline(time.Now().Add(150*time.Second)))
	call, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	require.NoError(e.t, err)
	_, err = fmt.Fprintf(conn, "%s\n%s\n", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, call)
	require.NoError(e.t, err)
	r := bufio.NewReaderSize(conn, 4<<20)
	_, err = r.ReadString('\n')
	require.NoError(e.t, err)
	line, err := r.ReadString('\n')
	require.NoError(e.t, err)
	var resp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(e.t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(e.t, resp.Result.Content, 1, line)
	var body map[string]any
	require.NoError(e.t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &body), line)
	return body, resp.Result.IsError
}

// heldAnswer is the agent's APPROVAL_REQUIRED answer to a write.
type heldAnswer struct {
	approvalID string
	runID      string
	link       string
	headline   string
	took       time.Duration
}

// hold makes the agent write 15 rows, which the guard holds, and returns
// its answer.
func (e *liveEngine) hold(intent string, status any) heldAnswer {
	e.t.Helper()
	run, isError := e.tool("run_start", map[string]any{"intent": intent})
	require.False(e.t, isError, "%v", run)
	start := time.Now()
	body, isError := e.tool("write", map[string]any{
		"sql": "UPDATE public.leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{status, 21, 35}, "intent": intent,
		"runId": run["runId"],
	})
	took := time.Since(start)
	require.True(e.t, isError, "%v", body)
	require.Equal(e.t, "APPROVAL_REQUIRED", body["code"], "%v", body)
	ap, ok := body["approval"].(map[string]any)
	require.True(e.t, ok, "%v", body)
	return heldAnswer{approvalID: ap["approvalId"].(string), runID: run["runId"].(string), link: ap["approvalUrl"].(string), headline: ap["headline"].(string), took: took}
}

// notice is one approval.deliver event the notifier recorded.
type recordedNotice struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Kind        string `json:"kind"`
		Agent       string `json:"agent"`
		ApprovalID  string `json:"approvalId"`
		Headline    string `json:"headline"`
		Link        string `json:"link"`
		LinkOpens   string `json:"linkOpens"`
		Instruction string `json:"instruction"`
	} `json:"data"`
	raw string
}

// records are the calls the notifier got so far, by hook.
func (e *notifierEngine) records() (notices []recordedNotice, feedTypes []string, raw []testnotifier.Record) {
	e.t.Helper()
	recs, err := testnotifier.ReadRecords(e.record)
	if err != nil {
		return nil, nil, nil // not written yet
	}
	for _, r := range recs {
		switch r.Hook {
		case testnotifier.HookApprovalDeliver:
			n := recordedNotice{raw: string(r.Event)}
			require.NoError(e.t, json.Unmarshal(r.Event, &n), string(r.Event))
			require.Equal(e.t, "product_a", r.Agent)
			notices = append(notices, n)
		case testnotifier.HookFeedObserve:
			for _, ev := range r.Events {
				var fe struct {
					Type string `json:"type"`
				}
				require.NoError(e.t, json.Unmarshal(ev, &fe))
				feedTypes = append(feedTypes, fe.Type)
			}
		}
	}
	return notices, feedTypes, recs
}

// noticeFor waits for the notice of approval id and returns it.
func (e *notifierEngine) noticeFor(id string) recordedNotice {
	e.t.Helper()
	var got recordedNotice
	require.Eventually(e.t, func() bool {
		notices, _, _ := e.records()
		for _, n := range notices {
			if n.Data.ApprovalID == id {
				got = n
				return true
			}
		}
		return false
	}, 100*time.Second, 50*time.Millisecond, "the notice of %s reaches the notifier", id) // its four tries span a minute
	return got
}

// TestNotifierEndToEnd is the notifier's whole path on a real engine and a
// real database: the agent installs the notifier through the approval
// flow, then holds a write. The plugin gets the notice, whose link is the
// one in the agent's own answer, byte for byte, and the held write as a
// feed event; nothing was issued or revoked for it.
func TestNotifierEndToEnd(t *testing.T) {
	bin := buildNotifier(t)
	t.Parallel()
	e := newNotifierEngine(t, bin, testnotifier.Options{})

	held := e.hold("Leads 21 to 35 went cold", "closed")
	require.Contains(t, held.link, "#2.", "no pages on this engine: the long link")
	n := e.noticeFor(held.approvalID)
	require.Equal(t, held.link, n.Data.Link, "exactly the link in the agent's answer")
	require.Equal(t, "dev.basaltdb.approval.requested", n.Type)
	require.Equal(t, "APPROVAL_REQUESTED", n.Data.Kind)
	require.Equal(t, "product_a", n.Data.Agent)
	require.Equal(t, "Update 15 rows in public·leads", n.Data.Headline)
	require.Equal(t, "Update 15 rows in public.leads", held.headline)
	require.Equal(t, "ENGINE_COMPUTER", n.Data.LinkOpens)
	require.Equal(t, "Open the link on the computer Basalt runs on to review the held write and approve it with your passkey.", n.Data.Instruction)

	// The link the plugin got is the agent's request, which the person's
	// passkey can sign: the agent then applies the write with the code.
	req, b, err := approval.ParseRequest(n.Data.Link[strings.Index(n.Data.Link, "#")+1:])
	require.NoError(t, err)
	require.Equal(t, held.approvalID, b.ApprovalID.String())
	as, err := e.pk.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := approval.NewResponse(b.ApprovalID, as).Code()
	require.NoError(t, err)
	body, isError := e.tool("write", map[string]any{
		"sql": "UPDATE public.leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", 21, 35},
		"intent": "Leads 21 to 35 went cold", "runId": held.runID, "approvalId": held.approvalID, "approval": code,
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])

	// The same write reaches the plugin as feed events.
	require.Eventually(t, func() bool {
		_, types, _ := e.records()
		return strings.Contains(strings.Join(types, " "), "dev.basaltdb.write.held") &&
			strings.Contains(strings.Join(types, " "), "dev.basaltdb.approval.signed")
	}, 60*time.Second, 100*time.Millisecond, "the held write and its signature arrive as feed events")
	notices, _, _ := e.records()
	require.Len(t, notices, 1, "one notice, delivered once")
	require.Empty(t, e.pluginProblems())
}

// TestHeldWriteNotSlowedByDeadNotifier: on a real engine, a notifier that
// never answers, one that answers after ten minutes and one that exits on
// the call leave the agent's answer to a held write as it is: the same
// answer, with its link, and the agent goes on working. That the answer
// does not wait at all, not even for one try, is proven without a clock in
// internal/engine (TestDeliverLinkNeverBlocks): what runs on the agent's
// call returns while the plugin, the database and the delivery are held.
func TestHeldWriteNotSlowedByDeadNotifier(t *testing.T) {
	bin := buildNotifier(t)
	t.Parallel()
	for _, mode := range []testnotifier.Mode{testnotifier.ModeHang, testnotifier.ModeLate, testnotifier.ModeCrash} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			e := newNotifierEngine(t, bin, testnotifier.Options{Delay: 10 * time.Minute})
			first := e.hold("Leads went cold", "closed")
			e.noticeFor(first.approvalID) // the notifier works, and the sender is up

			require.NoError(t, testnotifier.SetMode(e.control, mode))
			held := e.hold("Leads went cold again", "lost")
			require.Less(t, held.took, time.Minute)
			require.Contains(t, held.link, "#2.")
			require.Equal(t, first.headline, held.headline)
			require.NotEqual(t, first.approvalID, held.approvalID)

			// The plugin got the call, in that mode, and has not answered
			// it: the agent had its answer first.
			n := e.noticeFor(held.approvalID)
			require.Equal(t, held.link, n.Data.Link)
			_, _, recs := e.records()
			var modes []testnotifier.Mode
			for _, r := range recs {
				if r.Hook == testnotifier.HookApprovalDeliver && strings.Contains(string(r.Event), held.approvalID) {
					modes = append(modes, r.Mode)
				}
			}
			require.Contains(t, modes, mode)

			// And the agent goes on working while the plugin is stuck.
			third := e.hold("One more", "stale")
			require.Less(t, third.took, time.Minute)
			require.Contains(t, third.link, "#2.")
		})
	}
}

// leakMarker is in every value, parameter and intent of the leak test.
const leakMarker = "ZQXMARK"

// TestNothingLeaksToNotifier: a held write whose rows, parameters and
// intent carry a marker reaches the notifier as a notice and as feed
// events. Outside the notice's link, the one stated exception, nothing the
// plugin received holds the marker.
func TestNothingLeaksToNotifier(t *testing.T) {
	bin := buildNotifier(t)
	t.Parallel()
	e := newNotifierEngine(t, bin, testnotifier.Options{})
	body, isError := e.tool("write", map[string]any{
		"sql": "UPDATE public.leads SET name = $1 WHERE id = 1", "params": []any{leakMarker + "-seeded"}, "intent": "seed a value " + leakMarker,
	})
	require.False(t, isError, "%v", body)

	held := e.hold("close them "+leakMarker, leakMarker+"-status")
	n := e.noticeFor(held.approvalID)
	require.Equal(t, held.link, n.Data.Link)
	require.Contains(t, n.raw, n.Data.Link)

	// The long link carries the request, values included: the stated
	// exception. Decoded, it holds the marker; that is what the consent
	// text of an approval.deliver plugin says.
	req, _, err := approval.ParseRequest(n.Data.Link[strings.Index(n.Data.Link, "#")+1:])
	require.NoError(t, err)
	decoded, err := json.Marshal(req)
	require.NoError(t, err)
	require.Contains(t, string(decoded), leakMarker, "the link is the request itself")

	require.Eventually(t, func() bool {
		_, types, _ := e.records()
		return strings.Contains(strings.Join(types, " "), "dev.basaltdb.write.held")
	}, 60*time.Second, 100*time.Millisecond)
	_, _, recs := e.records()
	require.NotEmpty(t, recs)
	for _, r := range recs {
		rest := strings.ReplaceAll(string(r.Event), n.Data.Link, "")
		require.NotContains(t, rest, leakMarker, "a notice field outside the link holds a value, a parameter or the intent")
		for _, ev := range r.Events {
			require.NotContains(t, string(ev), leakMarker, "a feed event holds a value, a parameter or the intent")
		}
	}
}
