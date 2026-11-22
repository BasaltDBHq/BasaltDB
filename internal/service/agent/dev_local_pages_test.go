package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/config"
)

// devLocalSaved are init's saved flags on a development engine.
// devLocalStatus is the status report of an agent-operated engine on
// development pages.
func devLocalStatus(t *testing.T, operatedBy string) StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Status.DevLocalPages = true
	d.Status.Probe = &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

func TestDevLocalPagesStepIsTheAgentsInit(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	b := NewSteps()
	person := devLocalPagesSteps(b, cmds.OperatedBy(mcpcontract.OperatedByAgent))
	steps, err := b.Build()
	require.NoError(t, err)
	require.Len(t, steps, 2)
	require.Equal(t, mcp.ActionAskPerson, steps[0].Action)
	require.Equal(t, mcp.NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionRunCommand, Text: steps[1].Text, Command: "basalt init --agent bot --remote"}, steps[1])
	require.NotContains(t, person, "basalt ", "the person runs no command")
}

func TestDevLocalPagesWarnsOnEveryPersonMessage(t *testing.T) {
	t.Parallel()
	d := deps()
	d.Status.OperatedBy = mcpcontract.OperatedByAgent
	d.Status.DevLocalPages = true
	d.Status.Probe = &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 0}) // NO_PASSKEY too: two problems
	d.Core.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	srv, _ := serverOf(NewService(d))
	body, isErr := serveCall(t, srv, toolStatus, map[string]any{})
	require.False(t, isErr)
	problems, ok := body["problems"].([]any)
	require.True(t, ok)
	codes := map[string]bool{}
	for _, p := range problems {
		pm, ok := p.(map[string]any)
		require.True(t, ok)
		codes[pm["code"].(string)] = true
		msg, ok := pm["personMessage"].(string)
		require.True(t, ok)
		require.True(t, strings.HasPrefix(msg, config.DevLocalPagesWarning+"\n\n"), msg)
		require.Equal(t, 1, strings.Count(msg, "DEV_LOCAL_PAGES:"), "the warning once, also on its own problem")
	}
	require.True(t, codes[problemDevLocalPages] && codes[problemNoPasskey], codes)
}

func TestNoWarningWithoutDevLocalPages(t *testing.T) {
	t.Parallel()
	srv, _ := degraded(t, &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}, nil)
	body, _ := serveCall(t, srv, toolStatus, map[string]any{})
	require.NotContains(t, body, "DEV_LOCAL_PAGES")
	for _, p := range body["problems"].([]any) {
		require.NotEqual(t, problemDevLocalPages, p.(map[string]any)["code"])
	}
}

func TestDevLocalErrorWarnsOnACopy(t *testing.T) {
	t.Parallel()
	te := &mcp.ToolError{Code: "APPROVAL_REQUIRED", PersonMessage: "Approve it.", Approval: &mcp.ApprovalNotice{PersonMessage: "Approve it."}}
	out := devLocalError(te)
	require.Equal(t, config.DevLocalPagesWarning+"\n\nApprove it.", out.PersonMessage)
	require.Equal(t, config.DevLocalPagesWarning+"\n\nApprove it.", out.Approval.PersonMessage)
	require.Equal(t, "Approve it.", te.PersonMessage, "the shared error is left as it is")
	require.Equal(t, "Approve it.", te.Approval.PersonMessage)
	require.Empty(t, devLocalError(&mcp.ToolError{Code: "INVALID_ARGUMENT"}).PersonMessage, "no message gets none")
}

func TestDevLocalResultWarnsAtAnyDepth(t *testing.T) {
	t.Parallel()
	type item struct {
		PersonMessage string `json:"personMessage,omitempty"`
		Rows          int64  `json:"rows"`
	}
	out, err := devLocalResult(map[string]any{
		"personMessage": "top",
		"items":         []item{{PersonMessage: "nested", Rows: 9007199254740993}, {Rows: 1}},
	})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.Equal(t, config.DevLocalPagesWarning+"\n\ntop", m["personMessage"])
	items := m["items"].([]any)
	require.Equal(t, config.DevLocalPagesWarning+"\n\nnested", items[0].(map[string]any)["personMessage"])
	require.Equal(t, "9007199254740993", items[0].(map[string]any)["rows"].(interface{ String() string }).String(), "numbers keep their text")
	require.NotContains(t, items[1].(map[string]any), "personMessage")
}
