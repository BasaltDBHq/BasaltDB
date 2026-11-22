package agent

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

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

const (
	casePluginApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000e5"
	casePluginUpload   = "0193a4c2-7d1e-7c3a-9f00-0000000000f6"
)

// pluginBinding is a level 3 binding (unknown publisher, local, not fenced
// in) as open_plugin_approval returns it.
const pluginBinding = `{"kind": "PLUGIN", "name": "local-ner", "hooks": ["wire.detect"], "roles": ["VALUE"], "agents": ["basalt_agent_bot"], ` +
	`"egress": [], "signer": "UNKNOWN", "version": "0.3.1", "database": "app", "endpoint": {"kind": "LOCAL"}, "instance": "default", ` +
	`"expiresAt": "2026-11-13T09:00:00.000000Z", "isolation": {"files": "NONE", "network": "NOT_ENFORCED"}, ` +
	`"approvalId": "` + casePluginApproval + `", "requestedBy": "basalt_agent_bot", ` +
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
func pluginService(t *testing.T, f *fakePluginRequests) *Service {
	t.Helper()
	s := resultService(t, "linux", "")
	s.PluginRequests = f
	s.Poll = time.Millisecond
	setApprovals(&s.Deps, keys{n: 1})
	return s
}

func uploadMeta() json.RawMessage {
	return json.RawMessage(`{"` + mcp.MetaPluginUpload + `": {"uploadId": "` + casePluginUpload + `", "name": "local-ner", "executables": ["bin/ner"]}}`)
}

func callPlugin(t *testing.T, s *Service, args map[string]any, meta json.RawMessage) (requestPluginResult, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	require.NoError(t, err)
	var a requestPluginArgs
	if err := decodeArgs(raw, &a); err != nil {
		return requestPluginResult{}, err
	}
	if err := a.check(); err != nil {
		return requestPluginResult{}, err
	}
	return s.RequestPlugin(context.Background(), a, meta)
}

func requireReason(t *testing.T, err error, code, reason string) *mcp.ToolError {
	t.Helper()
	te := ToolError(err)
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
		set          func(s *Service)
	}{
		{"agent operated service", ReasonPluginAgentOperated, func(s *Service) { s.Commands = s.Commands.OperatedBy(mcpcontract.OperatedByAgent) }},
		{"agent operated without engine-kept plugins", ReasonPluginAgentOperated, func(s *Service) {
			s.Commands, s.SameUser, s.PluginRequests = s.Commands.OperatedBy(mcpcontract.OperatedByAgent), true, nil
		}},
		{"same user", ReasonPluginSameUserMode, func(s *Service) { s.SameUser = true }},
		{"no engine-kept plugins", ReasonPluginSameUserMode, func(s *Service) { s.PluginRequests = nil }},
		{"no local pages", ReasonPluginNoLocalPages, func(s *Service) { s.PagesOrigin = "" }},
	} {
		t.Run(kase.name, func(t *testing.T) {
			t.Parallel()
			f := &fakePluginRequests{opened: openedPlugin()}
			s := pluginService(t, f)
			kase.set(s)
			_, err := callPlugin(t, s, map[string]any{"source": "/home/me/local-ner"}, uploadMeta())
			requireReason(t, err, codePluginRefused, kase.reason)
			require.Empty(t, f.opens, "nothing is asked of the engine")
			if s.PluginRequests != nil {
				require.Equal(t, []uuid.UUID{uuid.MustParse(casePluginUpload)}, f.dropped, "the refused call's upload is dropped")
			}
		})
	}
	// Removing needs no page.
	f := &fakePluginRequests{}
	s := pluginService(t, f)
	s.PagesOrigin = ""
	_, err := callPlugin(t, s, map[string]any{"name": "local-ner", "remove": true}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"local-ner/default"}, f.removes)
}

// Exactly one form per call; no argument carries a signature, a code or
// settings.
func TestRequestPluginArguments(t *testing.T) {
	t.Parallel()
	for _, args := range []map[string]any{
		{},
		{"source": "/p", "name": "local-ner"},
		{"name": "local-ner", "approvalId": casePluginApproval},
		{"approvalId": casePluginApproval, "instance": "x"},
		{"approvalId": casePluginApproval, "remove": false},
		{"name": "local-ner", "waitForApproval": 5},
		{"source": "/p", "remove": true},
		{"name": "local-ner", "remove": true, "agents": []string{"bot"}},
		{"source": "relative/path"},
		{"approvalId": casePluginApproval, "signature": "basalt-plugin.1.x"},
		{"source": "/p", "settings": map[string]any{"config": map[string]any{}}},
		{"source": "/p", "config": map[string]any{}},
		{"source": "/p", "auth": map[string]any{}},
	} {
		f := &fakePluginRequests{opened: openedPlugin()}
		_, err := callPlugin(t, pluginService(t, f), args, uploadMeta())
		requireReason(t, err, CodeInvalidArgument, "")
		require.Empty(t, f.opens, "%v", args)
	}
}

// source needs basalt mcp's upload in _meta: without it the engine is not
// asked, so no path the agent names is ever opened by the engine.
func TestRequestPluginNeedsTheShimsUpload(t *testing.T) {
	t.Parallel()
	for _, meta := range []json.RawMessage{nil, json.RawMessage(`{}`), json.RawMessage(`{"` + mcp.MetaPluginUpload + `": {"uploadId": "nope", "name": "x"}}`)} {
		f := &fakePluginRequests{opened: openedPlugin()}
		_, err := callPlugin(t, pluginService(t, f), map[string]any{"source": "/home/me/local-ner"}, meta)
		requireReason(t, err, CodeInvalidArgument, "")
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
	require.Equal(t, []mcp.Link{{Label: "Approve the plugin local-ner", URL: out.ApprovalURL}}, out.Links)
	require.Contains(t, out.PersonMessage, "bot asks you to approve the plugin local-ner 0.3.1.")
	require.Contains(t, out.PersonMessage, pluginLevelUnknownHere)
	require.Contains(t, out.PersonMessage, "Approve it with your passkey only if you know who made it:")
	require.Contains(t, out.PersonMessage, "\n"+out.ApprovalURL+"\n")
	require.Len(t, out.NextSteps, 2)
	require.Equal(t, mcp.ActionOpenLink, out.NextSteps[0].Action)
	require.Equal(t, mcp.ActionCallTool, out.NextSteps[1].Action)
	require.Equal(t, map[string]any{"approvalId": casePluginApproval}, out.NextSteps[1].Arguments)

	// With no passkey registered, the person registers one first.
	f = &fakePluginRequests{opened: openedPlugin()}
	s = pluginService(t, f)
	setApprovals(&s.Deps, keys{n: 0})
	out, err = callPlugin(t, s, map[string]any{"source": "/home/me/local-ner"}, uploadMeta())
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(out.PersonMessage, "Nobody can approve this yet"), out.PersonMessage)
	require.Equal(t, mcp.ActionRunCommand, out.NextSteps[0].Action)

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
	requireReason(t, err, CodeNotFound, "")

	// No entry holds it any more (removed, or replaced for every agent), but
	// the caller's guard still has it: ENDED.
	s := pluginService(t, &fakePluginRequests{err: ErrPluginNotFound})
	s.PluginApprovals = endedApprovals{id: uuid.MustParse(casePluginApproval)}
	out, err = callPlugin(t, s, map[string]any{"approvalId": casePluginApproval}, nil)
	require.NoError(t, err)
	require.Equal(t, PluginStateEnded, out.State)
	require.Equal(t, "local-ner", out.Name)
}

// endedApprovals is the caller's guard holding one plugin approval.
type endedApprovals struct{ id uuid.UUID }

func (e endedApprovals) ReadPluginApproval(_ context.Context, id uuid.UUID) (guard.PluginApprovalRecord, bool, error) {
	if id != e.id {
		return guard.PluginApprovalRecord{}, false, nil
	}
	return guard.PluginApprovalRecord{ApprovalID: id, Name: "local-ner", Instance: "default", Status: guard.PluginApprovalStatusCancelled}, true, nil
}

func (endedApprovals) SubmitPluginApproval(context.Context, guard.PluginApprovalResponse) (time.Time, error) {
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

func pluginResultCases() map[string]resultCase {
	state := func(st string) func(*testing.T, *Service) (string, []mcp.Link, []mcp.NextStep) {
		return func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
			out, err := s.pluginWaited(uuid.MustParse(casePluginApproval), PluginApprovalState{
				Name: "local-ner", Instance: "default", Agents: []string{"bot"}, State: st, ExpiresAt: s.Now().Add(time.Hour),
			}, true)
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	wait := map[string]any{"approvalId": casePluginApproval}
	call := func(args map[string]any, opened PluginOpened) func(*testing.T, *Service) (string, []mcp.Link, []mcp.NextStep) {
		return func(t *testing.T, s *Service) (string, []mcp.Link, []mcp.NextStep) {
			s.PluginRequests = &fakePluginRequests{opened: opened}
			setApprovals(&s.Deps, keys{n: 1})
			out, err := callPlugin(t, s, args, uploadMeta())
			require.NoError(t, err)
			return out.PersonMessage, out.Links, out.NextSteps
		}
	}
	narrowed := openedPlugin()
	narrowed.Narrowed = true
	source := map[string]any{"source": "/home/me/local-ner"}
	remove := map[string]any{"name": "local-ner", "remove": true}
	return map[string]resultCase{
		resultKey(toolRequestPlugin, "REQUESTED"):  {tool: toolRequestPlugin, args: source, build: call(source, openedPlugin())},
		resultKey(toolRequestPlugin, "WAIT_ENDED"): {tool: toolRequestPlugin, args: wait, build: state(PluginStatePending), openWithoutURL: true},
		resultKey(toolRequestPlugin, "APPROVED"):   {tool: toolRequestPlugin, args: wait, build: state(PluginStateApproved)},
		resultKey(toolRequestPlugin, "RUNNING"):    {tool: toolRequestPlugin, args: wait, build: state(PluginStateRunning)},
		resultKey(toolRequestPlugin, "ENDED"):      {tool: toolRequestPlugin, args: wait, build: state(PluginStateEnded)},
		resultKey(toolRequestPlugin, "NARROWED"):   {tool: toolRequestPlugin, args: source, build: call(source, narrowed)},
		resultKey(toolRequestPlugin, "REMOVED"):    {tool: toolRequestPlugin, args: remove, build: call(remove, PluginOpened{})},
	}
}

// pluginCatalogCases raise each PLUGIN_REFUSED reason: the tool's own
// refusals by the engine they are refused on, the engine's through the
// fake.
func pluginCatalogCases() map[string]catalogCase {
	source := map[string]any{"source": "/home/me/local-ner"}
	own := func(set func(s *Service)) func(*testing.T, *Service) error {
		return func(t *testing.T, s *Service) error {
			s.PluginRequests = &fakePluginRequests{}
			set(s)
			_, err := callPlugin(t, s, source, uploadMeta())
			return err
		}
	}
	engine := func(reason string) func(*testing.T, *Service) error {
		return func(t *testing.T, s *Service) error {
			s.PagesOrigin = "http://localhost:7878"
			s.PluginRequests = &fakePluginRequests{err: &PluginRefusedError{Reason: reason, Message: "refused: " + reason}}
			_, err := callPlugin(t, s, source, uploadMeta())
			return err
		}
	}
	cases := map[string]catalogCase{
		caseKey(codePluginRefused, ReasonPluginAgentOperated, toolRequestPlugin): {toolRequestPlugin, source, own(func(s *Service) {
			s.Commands = s.Commands.OperatedBy(mcpcontract.OperatedByAgent)
		})},
		caseKey(codePluginRefused, ReasonPluginSameUserMode, toolRequestPlugin): {toolRequestPlugin, source, own(func(s *Service) { s.SameUser = true })},
		caseKey(codePluginRefused, ReasonPluginNoLocalPages, toolRequestPlugin): {toolRequestPlugin, source, own(func(s *Service) { s.PagesOrigin = "" })},
		caseKey(codePluginRefused, ReasonPluginNoPortalLink, toolRequestPlugin): {toolRequestPlugin, source, own(func(s *Service) {
			s.Commands, s.SameUser, s.PagesOrigin = s.Commands.OperatedBy(mcpcontract.OperatedByAgent), true, ""
		})},
	}
	for _, reason := range []string{
		ReasonPluginAgentNotAllowed, "BAD_MANIFEST", "NOT_TRUSTED", "UNKNOWN_AGENT", "UNSAFE_PATH", "TOO_MANY_PENDING", "GUARD_OUTDATED",
		"DATABASE_UNREACHABLE", "NAME_TAKEN", "CONFIG_ENTRY", "TOO_LARGE", "TOO_MANY_UPLOADS", "ENGINE_IS_ROOT",
	} {
		cases[caseKey(codePluginRefused, reason, toolRequestPlugin)] = catalogCase{toolRequestPlugin, source, engine(reason)}
	}
	return cases
}
