package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// slowPrepare is a revert store whose prepare runs into its time limit,
// recording the limit it was given; nothing else is called.
type slowPrepare struct {
	RevertStore
	timeout *time.Duration
}

func (s slowPrepare) PrepareRevert(_ context.Context, _ guard.RevertScope, _ string, timeout time.Duration) (guard.PreparedRevert, error) {
	*s.timeout = timeout
	return guard.PreparedRevert{}, &pgconn.PgError{Code: sqlStateQueryCanceled, Message: "canceling statement due to statement timeout"}
}

// A prepare too large for an MCP call is QUERY_TIMEOUT, and its message
// hands the person the complete command to prepare it in a terminal.
func TestRequestRevertPrepareTimeLimit(t *testing.T) {
	t.Parallel()
	var limit time.Duration
	d := deps()
	d.Reverts = slowPrepare{timeout: &limit}
	d.CLIFlags = "--agent bot"
	d.FullCLIFlags = "--agent bot --config /etc/basalt/engine.json"
	svc := NewService(d)
	run := uuid.Must(uuid.NewV7())

	_, err := svc.RequestRevert(context.Background(), RequestRevertParams{
		Scope: guard.RevertScope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo",
	})
	require.Equal(t, guard.MCPPrepareTimeout, limit)
	require.Equal(t, 100*time.Second, limit, "under Claude Code's 2-minute auto-background")
	var te *mcp.ToolError
	require.True(t, errors.As(err, &te), "%v", err)
	require.Equal(t, CodeQueryTimeout, te.Code)
	require.Equal(t, ReasonTimeLimit, te.Reason)
	require.Contains(t, te.Message, "nothing was prepared")
	command := "basalt revert --agent bot --config /etc/basalt/engine.json --run " + run.String() + " --open"
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
	_, err = svc.RequestRevert(ctx, RequestRevertParams{Scope: guard.RevertScope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo"})
	require.Equal(t, CodeUnavailable, ToolError(err).Code)
}
