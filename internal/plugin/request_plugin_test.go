package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
)

const (
	casePluginApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000e5"
	casePluginUpload   = "0193a4c2-7d1e-7c3a-9f00-0000000000f6"
)

// pluginBinding is a level 3 binding (unknown publisher, local, not fenced
// in) as open_plugin_approval returns it.
const pluginBinding = `{"kind": "PLUGIN", "name": "local-ner", "hooks": ["wire.detect"], "roles": ["VALUE"], "store": {"kind": "POSTGRES", "name": "app"}, "agents": ["agent:bot"], ` +
	`"egress": [], "signer": "UNKNOWN", "version": "0.3.1", "endpoint": {"kind": "LOCAL"}, "instance": "default", ` +
	`"expiresAt": "2026-11-13T09:00:00.000000Z", "isolation": {"files": "NONE", "network": "NOT_ENFORCED"}, ` +
	`"approvalId": "` + casePluginApproval + `", "requestedBy": "agent:bot", ` +
	`"manifestSha256": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", ` +
	`"settingsSha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}`

// fakePluginRequests records what the tool asked the engine, and answers
// from its fields.
type fakePluginRequests struct {
	mu      sync.Mutex
	opens   []PluginOpen
	removes []string
	dropped []uuid.UUID
	reads   int
	opened  PluginOpened
	err     error
	states  []PluginApprovalState
}

func (f *fakePluginRequests) OpenPlugin(_ context.Context, caller string, p PluginOpen) (PluginOpened, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens = append(f.opens, p)
	if f.err != nil {
		return PluginOpened{}, f.err
	}
	return f.opened, nil
}

func (f *fakePluginRequests) RemovePlugin(_ context.Context, caller, name, instance string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes = append(f.removes, name+"/"+instance)
	return f.err
}

func (f *fakePluginRequests) DropUpload(_ string, id uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, id)
}

func (f *fakePluginRequests) PluginApproval(context.Context, string, uuid.UUID) (PluginApprovalState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return PluginApprovalState{}, f.err
	}
	i := min(f.reads, len(f.states)-1)
	f.reads++
	return f.states[i], nil
}

func openedPlugin() PluginOpened {
	return PluginOpened{
		Name: "local-ner", Instance: "default", Version: "0.3.1", Agents: []string{"bot"},
		ApprovalID: uuid.MustParse(casePluginApproval), ExpiresAt: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), BindingText: pluginBinding,
	}
}

// pluginService is a person-operated service engine with local pages and
// the fake engine-kept plugins.
func pluginService(t *testing.T, f *fakePluginRequests, opts ...option) *Service {
	t.Helper()
	return newService(t, "linux", "", append([]option{withRequests(f)}, opts...)...)
}

func uploadMeta() json.RawMessage {
	return json.RawMessage(`{"` + metaPluginUpload + `": {"uploadId": "` + casePluginUpload + `", "name": "local-ner", "executables": ["bin/ner"]}}`)
}

// callPlugin makes the call the tool's controller makes once it has decoded
// args: the decoded fields go to the use case as parameters.
func callPlugin(t *testing.T, s *Service, args map[string]any, meta json.RawMessage) (requestPluginResult, error) {
	t.Helper()
	text := func(k string) string { v, _ := args[k].(string); return v }
	agents, _ := args["agents"].([]string)
	var remove *bool
	if v, ok := args["remove"].(bool); ok {
		remove = &v
	}
	var wait *int
	if v, ok := args["waitForApproval"].(int); ok {
		wait = &v
	}
	return s.RequestPlugin(context.Background(), text("source"), text("name"), text("instance"), agents, remove, text("approvalId"), wait, meta)
}

func requireReason(t *testing.T, err error, code, reason string) *toolresult.ToolError {
	t.Helper()
	te := pgerrors.Map().ToolError(err)
	require.Equal(t, code, te.Code, te.Message)
	require.Equal(t, reason, te.Reason)
	return te
}

// The tool is refused, before the engine is asked anything, wherever it is
// not served: an agent-operated service engine, a person-operated
// same-user engine, and an engine without local pages for a call that
// opens an approval.
func TestRequestPluginRefusedWhereNotServed(t *testing.T) {
	t.Parallel()
	for _, kase := range []struct {
		name, reason string
		set          option
	}{
		{"agent operated service", ReasonPluginAgentOperated, agentOperated},
		{"agent operated without engine-kept plugins", ReasonPluginAgentOperated, func(s *serviceSettings) {
			agentOperated(s)
			s.status.sameUser, s.deps.Requests = true, nil
		}},
		{"same user", ReasonPluginSameUserMode, withSameUser},
		{"no engine-kept plugins", ReasonPluginSameUserMode, func(s *serviceSettings) { s.deps.Requests = nil }},
		{"no local pages", ReasonPluginNoLocalPages, withoutLocalPages},
	} {
		t.Run(kase.name, func(t *testing.T) {
			t.Parallel()
			f := &fakePluginRequests{opened: openedPlugin()}
			s := pluginService(t, f, kase.set)
			_, err := callPlugin(t, s, map[string]any{"source": "/home/me/local-ner"}, uploadMeta())
			requireReason(t, err, codePluginRefused, kase.reason)
			require.Empty(t, f.opens, "nothing is asked of the engine")
			if s.deps.Requests != nil {
				require.Equal(t, []uuid.UUID{uuid.MustParse(casePluginUpload)}, f.dropped, "the refused call's upload is dropped")
			}
		})
	}
	// Removing needs no page.
	f := &fakePluginRequests{}
	s := pluginService(t, f, withoutLocalPages)
	_, err := callPlugin(t, s, map[string]any{"name": "local-ner", "remove": true}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"local-ner/default"}, f.removes)
}

// source needs basalt mcp's upload in _meta: without it the engine is not
// asked, so no path the agent names is ever opened by the engine.
func TestRequestPluginNeedsTheShimsUpload(t *testing.T) {
	t.Parallel()
	for _, meta := range []json.RawMessage{nil, json.RawMessage(`{}`), json.RawMessage(`{"` + metaPluginUpload + `": {"uploadId": "nope", "name": "x"}}`)} {
		f := &fakePluginRequests{opened: openedPlugin()}
		_, err := callPlugin(t, pluginService(t, f), map[string]any{"source": "/home/me/local-ner"}, meta)
		requireReason(t, err, guidance.CodeInvalidArgument, "")
		require.Empty(t, f.opens)
	}
}

// A new approval: the engine gets the upload, the manifest's name and the
// agents as given (nil: the engine's default, never every agent); the
// result carries the short link on the local pages, the page's level line
// and the one wait.
func TestRequestPluginOpensAnApproval(t *testing.T) {
	t.Parallel()
	f := &fakePluginRequests{opened: openedPlugin()}
	s := pluginService(t, f)
	out, err := callPlugin(t, s, map[string]any{"source": "/home/me/local-ner"}, uploadMeta())
	require.NoError(t, err)
	require.Len(t, f.opens, 1)
	got := f.opens[0]
	require.Equal(t, casePluginUpload, got.UploadID.String())
	require.Equal(t, "local-ner", got.Name)
	require.Equal(t, "default", got.Instance)
	require.Equal(t, []string{"bin/ner"}, got.Executables)
	require.Nil(t, got.Agents, "no agents: the engine's default")

	require.Equal(t, PluginStatePending, out.State)
	require.Equal(t, casePluginApproval, out.ApprovalID)
	require.True(t, strings.HasPrefix(out.ApprovalURL, "http://localhost:7878/plugins/"+casePluginApproval+"#s="), out.ApprovalURL)
	require.Equal(t, []toolresult.Link{{Label: "Approve the plugin local-ner", URL: out.ApprovalURL}}, out.Links)
	require.Contains(t, out.PersonMessage, "bot asks you to approve the plugin local-ner 0.3.1.")
	require.Contains(t, out.PersonMessage, pluginLevelUnknownHere)
	require.Contains(t, out.PersonMessage, "Approve it with your passkey only if you know who made it:")
	require.Contains(t, out.PersonMessage, "\n"+out.ApprovalURL+"\n")
	require.Len(t, out.NextSteps, 2)
	require.Equal(t, toolresult.ActionOpenLink, out.NextSteps[0].Action)
	require.Equal(t, toolresult.ActionCallTool, out.NextSteps[1].Action)
	require.Equal(t, map[string]any{"approvalId": casePluginApproval}, out.NextSteps[1].Arguments)

	// With no passkey registered, the person registers one first.
	f = &fakePluginRequests{opened: openedPlugin()}
	s = pluginService(t, f, withPasskeys(0))
	out, err = callPlugin(t, s, map[string]any{"source": "/home/me/local-ner"}, uploadMeta())
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(out.PersonMessage, "Nobody can approve this yet"), out.PersonMessage)
	require.Equal(t, toolresult.ActionRunCommand, out.NextSteps[0].Action)

	// The name form opens a new approval for the installed copy: no upload.
	f = &fakePluginRequests{opened: openedPlugin()}
	_, err = callPlugin(t, pluginService(t, f), map[string]any{"name": "local-ner", "instance": "client_x", "agents": []string{"bot", "other"}}, uploadMeta())
	require.NoError(t, err)
	require.Nil(t, f.opens[0].UploadID, "the name form ignores any upload")
	require.Equal(t, "client_x", f.opens[0].Instance)
	require.Equal(t, []string{"bot", "other"}, f.opens[0].Agents)
}

// The wait only reads: it never opens, removes or relays anything, and it
// returns once the engine runs the plugin on the approval.
func TestRequestPluginWaitOnlyReads(t *testing.T) {
	t.Parallel()
	pending := PluginApprovalState{Name: "local-ner", Instance: "default", Agents: []string{"bot"}, State: PluginStatePending, ExpiresAt: time.Now().Add(time.Hour)}
	running := pending
	running.State = PluginStateRunning
	f := &fakePluginRequests{states: []PluginApprovalState{pending, pending, running}}
	out, err := callPlugin(t, pluginService(t, f), map[string]any{"approvalId": casePluginApproval, "waitForApproval": 5}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStateRunning, out.State)
	require.Equal(t, 3, f.reads)
	require.Empty(t, f.opens)
	require.Empty(t, f.removes)
	require.Empty(t, out.ApprovalURL, "the wait hands over no link")
	require.Empty(t, out.Links)

	f = &fakePluginRequests{states: []PluginApprovalState{pending}}
	out, err = callPlugin(t, pluginService(t, f), map[string]any{"approvalId": casePluginApproval, "waitForApproval": 0}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStatePending, out.State)
	require.Equal(t, 1, f.reads)

	f = &fakePluginRequests{err: ErrPluginNotFound}
	_, err = callPlugin(t, pluginService(t, f), map[string]any{"approvalId": casePluginApproval}, nil)
	requireReason(t, err, guidance.CodeNotFound, "")

	// No entry holds it any more (removed, or replaced for every agent), but
	// the caller's guard still has it: ENDED.
	s := pluginService(t, &fakePluginRequests{err: ErrPluginNotFound}, withApprovals(endedApprovals{id: uuid.MustParse(casePluginApproval)}))
	out, err = callPlugin(t, s, map[string]any{"approvalId": casePluginApproval}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStateEnded, out.State)
	require.Equal(t, "local-ner", out.Name)
}

// endedApprovals is the caller's guard holding one plugin approval.
type endedApprovals struct{ id uuid.UUID }

func (e endedApprovals) ReadPluginApproval(_ context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	if id != e.id {
		return guardmodel.PluginApprovalRecord{}, false, nil
	}
	return guardmodel.PluginApprovalRecord{ApprovalID: id, Name: "local-ner", Instance: "default", Status: guardmodel.PluginApprovalStatusCancelled}, true, nil
}

func (endedApprovals) SubmitPluginApproval(context.Context, guardmodel.PluginApprovalResponse) (time.Time, error) {
	return time.Time{}, errors.New("never")
}

// The engine's refusals reach the agent as PLUGIN_REFUSED with their
// reason; a narrowing needs no approval.
func TestRequestPluginEngineAnswers(t *testing.T) {
	t.Parallel()
	f := &fakePluginRequests{err: &PluginRefusedError{Reason: ReasonPluginAgentNotAllowed, Message: "agent other uses another database"}}
	_, err := callPlugin(t, pluginService(t, f), map[string]any{"source": "/p"}, uploadMeta())
	te := requireReason(t, err, codePluginRefused, ReasonPluginAgentNotAllowed)
	require.Contains(t, te.PersonMessage, "another database")

	f = &fakePluginRequests{opened: PluginOpened{Name: "local-ner", Instance: "default", Version: "0.3.1", Agents: []string{"bot"}, Narrowed: true}}
	out, err := callPlugin(t, pluginService(t, f), map[string]any{"name": "local-ner", "agents": []string{"bot"}}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStateNarrowed, out.State)
	require.Empty(t, out.ApprovalID)
}
