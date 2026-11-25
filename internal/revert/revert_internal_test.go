package revert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// slowPrepare is a revert store whose prepare runs into its time limit, as
// the Postgres store answers it, recording the limit it was given; nothing
// else is called.
type slowPrepare struct {
	Store
	timeout *time.Duration
}

func (s slowPrepare) PrepareRevert(_ context.Context, _ action.Scope, _ string, timeout time.Duration) (action.PreparedRevert, error) {
	*s.timeout = timeout
	canceled := store.MapError(&pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"})
	return action.PreparedRevert{}, &action.RevertRefusalError{Reason: action.RevertTimedOut, StoreCode: "57014", Err: canceled}
}

// A prepare too large for an MCP call is QUERY_TIMEOUT, and its message
// hands the person the complete command to prepare it in a terminal.
func TestRequestRevertPrepareTimeLimit(t *testing.T) {
	t.Parallel()
	var limit time.Duration
	svc := newService(t, "linux", "/etc/basalt-test/engine.json", withStore(slowPrepare{timeout: &limit}))
	run := uuid.Must(uuid.NewV7())

	_, err := svc.RequestRevert(context.Background(), RequestRevertParams{
		Scope: action.Scope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo",
	})
	require.Equal(t, guardmodel.MCPPrepareTimeout, limit)
	require.Equal(t, 100*time.Second, limit, "under Claude Code's 2-minute auto-background")
	var te *toolresult.ToolError
	require.True(t, errors.As(err, &te), "%v", err)
	require.Equal(t, guidance.CodeQueryTimeout, te.Code)
	require.Equal(t, guidance.ReasonTimeLimit, te.Reason)
	require.Contains(t, te.Message, "nothing was prepared")
	require.Contains(t, te.Message, "runs or tables")
	require.NotContains(t, te.Message, "basalt ", "no person command")
	require.NotContains(t, te.PersonMessage, "basalt ", "the person runs no command")
	kinds := make([]string, 0, len(te.NextSteps))
	for _, s := range te.NextSteps {
		kinds = append(kinds, s.Actor+" "+s.Action)
		require.Empty(t, s.Command)
	}
	require.Equal(t, []string{"AGENT STOP", "AGENT ASK_PERSON", "AGENT END_TURN"}, kinds,
		"api/mcp/errors/next-steps.json, QUERY_TIMEOUT TIME_LIMIT request_revert")

	// A call the client canceled is not the time limit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = svc.RequestRevert(ctx, RequestRevertParams{Scope: action.Scope{Kind: revert.ScopeRun, ID: run}, Intent: "Undo"})
	require.Equal(t, guidance.CodeUnavailable, testErrors().ToolError(err).Code)
}

// A preview that runs out names the agent's statement timeout it ran
// under, never request_revert's 100 seconds; request_revert keeps them.
func TestPreviewRevertTimeLimitNamesTheStatementTimeout(t *testing.T) {
	t.Parallel()
	s := newService(t, "linux", "", withStatementTimeout(5*time.Second))
	// A fixed id: a UUIDv7 starts with the clock, which can contain "100".
	scope := action.Scope{Kind: revert.ScopeRun, ID: uuid.MustParse("0190a2b3-4c5d-7e6f-8a9b-0c1d2e3f4a5b")}

	preview := testErrors().ToolError(s.prepareTimeout(guidance.ToolPreviewRevert, scope, "57014"))
	require.Equal(t, guidance.CodeQueryTimeout, preview.Code)
	require.Equal(t, guidance.ReasonTimeLimit, preview.Reason)
	require.Equal(t, "previewing the revert of run "+scope.ID.String()+" took longer than the agent's statement timeout of 5 seconds; "+
		"nothing was previewed. A narrower revert, with runs or tables, may fit.", preview.Message)
	require.NotContains(t, preview.Message, "100 seconds")

	request := testErrors().ToolError(s.prepareTimeout(guidance.ToolRequestRevert, scope, "57014"))
	require.Contains(t, request.Message, "took longer than the 100 seconds an MCP call may take")

	s = newService(t, "linux", "", withStatementTimeout(1500*time.Millisecond))
	require.Contains(t, testErrors().ToolError(s.prepareTimeout(guidance.ToolPreviewRevert, scope, "57014")).Message, "the agent's statement timeout of 1.5s;")
}

// countedReverts owns nothing and counts the guard calls it receives.
type countedReverts struct {
	Store
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
	svc := newService(t, "linux", "", withRuns(noRuns{}), withStore(countedReverts{guardCalls: &calls}))
	ctx := context.Background()
	for kind, reason := range map[revert.Scope]string{
		revert.ScopeChange: "CHANGE", revert.ScopeRun: "RUN", revert.ScopeTask: "TASK",
	} {
		scope := action.Scope{Kind: kind, ID: uuid.Must(uuid.NewV7())}
		_, err := svc.PreviewRevert(ctx, PreviewRevertParams{Scope: scope})
		require.Equal(t, guidance.CodeNotFound, testErrors().ToolError(err).Code, "%v", err)
		require.Equal(t, reason, testErrors().ToolError(err).Reason)
		_, err = svc.RequestRevert(ctx, RequestRevertParams{Scope: scope, Intent: "Undo"})
		require.Equal(t, guidance.CodeNotFound, testErrors().ToolError(err).Code, "%v", err)
		require.Equal(t, reason, testErrors().ToolError(err).Reason)
	}
	require.Zero(t, calls, "no guard call for a scope that is not the agent's")
}

// A store set with a nil port is refused when the service is built: the
// service reads the store only through the three ports.
func TestNewRefusesAStoreSetWithANilPort(t *testing.T) {
	t.Parallel()
	for name, breakIt := range map[string]func(*StoreSet){
		"Records": func(s *StoreSet) { s.Records = nil },
		"Undo":    func(s *StoreSet) { s.Undo = nil },
		"Proofs":  func(s *StoreSet) { s.Proofs = nil },
	} {
		set := storeSet(struct{ Store }{})
		breakIt(&set)
		require.PanicsWithValue(t, "revert: store set missing ports: "+name, func() {
			New(Core{}, set, &Deps{}, nil, nil, nil, nil)
		}, name)
	}
	require.NotPanics(t, func() { New(Core{}, storeSet(struct{ Store }{}), &Deps{}, nil, nil, nil, nil) })
}

// A store set without a prepare time limit is refused when the service is
// built: Postgres reads a zero statement timeout as no limit at all.
func TestNewRefusesAStoreSetWithoutAPrepareLimit(t *testing.T) {
	t.Parallel()
	for _, limit := range []time.Duration{0, -time.Second} {
		set := storeSet(struct{ Store }{})
		set.Limits.Prepare = limit
		require.PanicsWithValue(t, "revert: store set has no prepare time limit", func() {
			New(Core{}, set, &Deps{}, nil, nil, nil, nil)
		}, limit.String())
	}
}
