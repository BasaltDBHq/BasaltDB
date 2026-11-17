package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// slowPrepare is a revert store whose prepare runs into its time limit,
// recording the limit it was given; nothing else is called.
type slowPrepare struct {
	Reverts
	timeout *time.Duration
}

func (s slowPrepare) PrepareRevert(_ context.Context, _ action.Scope, _ string, timeout time.Duration) (action.PreparedRevert, error) {
	*s.timeout = timeout
	return action.PreparedRevert{}, &pgconn.PgError{Code: sqlStateQueryCanceled, Message: "canceling statement due to statement timeout"}
}

// A prepare too large for an MCP call is QUERY_TIMEOUT, and its message
// hands the person the complete command to prepare it in a terminal.
func TestRequestRevertPrepareTimeLimit(t *testing.T) {
	t.Parallel()
	var limit time.Duration
	d := deps()
	setReverts(&d, slowPrepare{timeout: &limit})
	cmds, err := NewCommands("bot", "/etc/basalt-test/engine.json", "linux", nil)
	require.NoError(t, err)
	d.Commands = cmds
	svc := NewService(d)
	run := uuid.Must(uuid.NewV7())

	_, err = svc.RequestRevert(context.Background(), RequestRevertParams{
		Scope: action.Scope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo",
	})
	require.Equal(t, guard.MCPPrepareTimeout, limit)
	require.Equal(t, 100*time.Second, limit, "under Claude Code's 2-minute auto-background")
	var te *mcp.ToolError
	require.True(t, errors.As(err, &te), "%v", err)
	require.Equal(t, CodeQueryTimeout, te.Code)
	require.Equal(t, ReasonTimeLimit, te.Reason)
	require.Contains(t, te.Message, "nothing was prepared")
	command := "basalt revert --agent bot --config /etc/basalt-test/engine.json --run " + run.String() + " --open"
	require.Contains(t, te.Message, command)
	require.Contains(t, te.PersonMessage, command)
	kinds := make([]string, 0, len(te.NextSteps))
	for _, s := range te.NextSteps {
		kinds = append(kinds, s.Actor+" "+s.Action)
	}
	require.Equal(t, []string{"AGENT STOP", "PERSON RUN_COMMAND", "PERSON TELL_AGENT", "AGENT END_TURN"}, kinds,
		"api/mcp/errors/next-steps.json, QUERY_TIMEOUT TIME_LIMIT request_revert")
	require.Equal(t, command, te.NextSteps[1].Command)

	// A call the client canceled is not the time limit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = svc.RequestRevert(ctx, RequestRevertParams{Scope: action.Scope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo"})
	require.Equal(t, CodeUnavailable, ToolError(err).Code)
}

// noRuns is a Store that finds none of the agent's runs.
type noRuns struct{ nopStore }

func (noRuns) FindRun(context.Context, uuid.UUID) (action.Run, error) {
	return action.Run{}, action.ErrRunNotFound
}

// countedReverts owns nothing and counts the guard calls it receives.
type countedReverts struct {
	Reverts
	guardCalls *int
}

func (countedReverts) HasChange(context.Context, uuid.UUID) (bool, error)  { return false, nil }
func (countedReverts) HasTaskRun(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (r countedReverts) PreviewRevert(context.Context, action.Scope, string, int) (action.PreviewPage, error) {
	*r.guardCalls++
	return action.PreviewPage{}, nil
}

func (r countedReverts) PrepareRevert(context.Context, action.Scope, string, time.Duration) (action.PreparedRevert, error) {
	*r.guardCalls++
	return action.PreparedRevert{}, nil
}

// TestNotOwnScopeBeforeAnyGuardCall: preview_revert and request_revert
// check the agent's own change, run or task first (RS-1), so a scope that
// is not its own never reaches the guard.
func TestNotOwnScopeBeforeAnyGuardCall(t *testing.T) {
	t.Parallel()
	var calls int
	d := deps()
	setRuns(&d, noRuns{})
	setReverts(&d, countedReverts{guardCalls: &calls})
	svc := NewService(d)
	ctx := context.Background()
	for kind, reason := range map[revert.Scope]string{
		revert.ScopeChange: "CHANGE", revert.ScopeRun: "RUN", revert.ScopeTask: "TASK",
	} {
		scope := action.Scope{Kind: kind, ID: uuid.Must(uuid.NewV7())}
		_, err := svc.PreviewRevert(ctx, PreviewRevertParams{Scope: scope})
		require.Equal(t, CodeNotFound, ToolError(err).Code, "%v", err)
		require.Equal(t, reason, ToolError(err).Reason)
		_, err = svc.RequestRevert(ctx, RequestRevertParams{Scope: scope, Intent: "Undo"})
		require.Equal(t, CodeNotFound, ToolError(err).Code, "%v", err)
		require.Equal(t, reason, ToolError(err).Reason)
	}
	require.Zero(t, calls, "no guard call for a scope that is not the agent's")
}
