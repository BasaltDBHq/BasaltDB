package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func TestStepBuilderOneConstructorPerAction(t *testing.T) {
	t.Parallel()
	steps, err := NewSteps().
		CallTool("status", map[string]any{"verbose": true}, "Check status.").
		ReviseCall("write", map[string]any{"runId": "r"}, "Add an intent.").
		RetrySmallerBatches(50, "Only on an explicit yes.").
		AskPerson("Ask the person.").
		EndTurn("End your turn.").
		Stop("Do not retry.").
		OpenLink("http://localhost:7878/approvals/x#1.s", "", "Open it.").
		OpenLink("http://localhost:7878/approvals/x#1.s", "basalt approve --agent bot --open x", "Open it.").
		RunCommand("basalt upgrade --agent bot", "Run this.").
		TellAgent("Say go.").
		Build()
	require.NoError(t, err)
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Actor+" "+s.Action)
	}
	require.Equal(t, []string{
		"AGENT CALL_TOOL", "AGENT REVISE_CALL", "AGENT RETRY_SMALLER_BATCHES", "AGENT ASK_PERSON", "AGENT END_TURN",
		"AGENT STOP", "PERSON OPEN_LINK", "PERSON OPEN_LINK", "PERSON RUN_COMMAND", "PERSON TELL_AGENT",
	}, got)
	require.Equal(t, "status", steps[0].Tool)
	require.Equal(t, map[string]any{"verbose": true}, steps[0].Arguments)
	require.Equal(t, 50, steps[2].MaxRows)
	require.Empty(t, steps[6].Command)
	require.Equal(t, "basalt approve --agent bot --open x", steps[7].Command)
}

func TestStepBuilderRepeatCallAndWait(t *testing.T) {
	t.Parallel()
	steps, err := NewSteps().RepeatCall("write", map[string]any{"approvalId": "a"}, 5, "Call again.").Build()
	require.NoError(t, err)
	require.True(t, steps[0].RepeatCall)
	require.Equal(t, 5, steps[0].WaitSeconds)
	require.Equal(t, mcp.ActionCallTool, steps[0].Action)
}

func TestStepTextOverLimitIsRefusedAtBuildTime(t *testing.T) {
	t.Parallel()
	ok := strings.Repeat("a", MaxStepTextLength)
	_, err := NewSteps().AskPerson(ok).Build()
	require.NoError(t, err)

	_, err = NewSteps().AskPerson("fine").EndTurn(ok + "a").Build()
	require.ErrorIs(t, err, ErrStepText)
	_, err = NewSteps().AskPerson("").Build()
	require.ErrorIs(t, err, ErrStepText, "text is required")
}

func TestPersonMessageOverLimitIsRefusedAtBuildTime(t *testing.T) {
	t.Parallel()
	require.NoError(t, CheckPersonMessage(strings.Repeat("a", MaxPersonMessageLength)))
	require.ErrorIs(t, CheckPersonMessage(strings.Repeat("a", MaxPersonMessageLength+1)), ErrStepText)
	require.NoError(t, CheckPersonMessage(""), "optional")
}

func TestStepLimitsCountCharactersNotBytes(t *testing.T) {
	t.Parallel()
	_, err := NewSteps().AskPerson(strings.Repeat("é", MaxStepTextLength)).Build()
	require.NoError(t, err)
}

func TestStepBuilderRefusesBadFields(t *testing.T) {
	t.Parallel()
	_, err := NewSteps().CallTool("", nil, "x").Build()
	require.Error(t, err, "a tool is required")
	_, err = NewSteps().RunCommand("", "x").Build()
	require.Error(t, err, "a command is required")
	_, err = NewSteps().OpenLink("", "", "x").Build()
	require.Error(t, err, "a url is required")
	_, err = NewSteps().RetrySmallerBatches(0, "x").Build()
	require.Error(t, err)
	_, err = NewSteps().RetrySmallerBatches(MaxRetryRows+1, "x").Build()
	require.Error(t, err)
	_, err = NewSteps().Build()
	require.Error(t, err, "at least one step")
}
