package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

type nopReader struct{}

func (nopReader) Read(context.Context, string, []any, action.Statement) (action.ReadResult, error) {
	return action.ReadResult{}, nil
}

type nopRecorder struct{}

func (nopRecorder) RecordRead(context.Context, action.Read) (uuid.UUID, error) { return uuid.Nil, nil }

type nopStore struct{}

func (nopStore) FindRun(context.Context, uuid.UUID) (action.Run, error) { return action.Run{}, nil }
func (nopStore) StartRun(context.Context, action.Intent) error          { return nil }
func (nopStore) Write(context.Context, action.Intent, action.Op, string, []any) (action.WriteResult, error) {
	return action.WriteResult{}, nil
}
func (nopStore) RecordRefusal(context.Context, action.Refusal) error { return nil }
func (nopStore) History(context.Context, ledger.ChangeListParams) (History, error) {
	return History{}, nil
}

func (nopStore) ListRuns(context.Context, ledger.RunListParams) (pagination.Page[action.RunSummary], error) {
	return pagination.Page[action.RunSummary]{}, nil
}

func deps() Deps {
	return Deps{
		Name: "bot",
		Store: parts{
			reader: nopReader{}, runStore: nopStore{}, readRecorder: nopRecorder{},
			approvalStore: struct{ approvalStore }{}, // never called by these tests
			Reverts:       struct{ Reverts }{},
		},
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
	}
}

// TestServedToolsMatchTheContracts is the contract test for the served tool
// list (CONTRACT.md): every served tool has a contract, every IMPLEMENTED
// contract is served, and each tool lists its contract's schema.
func TestServedToolsMatchTheContracts(t *testing.T) {
	t.Parallel()
	contracts := mcpcontract.MustLoad()
	tools := Tools(NewService(deps()))
	served := make([]string, 0, len(tools))
	for _, tool := range tools {
		served = append(served, tool.Name)
		c, ok := mcpcontract.Find(contracts, tool.Name)
		require.True(t, ok)
		require.Equal(t, c.InputSchema, tool.InputSchema, tool.Name)
		require.Equal(t, c.Description, tool.Description, tool.Name)
	}
	require.NoError(t, mcpcontract.CheckServed(contracts, served))
}

// TestHeldWriteDescriptionsWaitOnce: after handing over a link (write's
// APPROVAL_REQUIRED or list_pending), the agent waits once with approvalId
// in the same turn, and never loops on a wait that ran out.
func TestHeldWriteDescriptionsWaitOnce(t *testing.T) {
	t.Parallel()
	contracts := mcpcontract.MustLoad()
	write, ok := mcpcontract.Find(contracts, "write")
	require.True(t, ok)
	require.Contains(t, write.Description, "without ending your turn, call write once with the same arguments plus approvalId")
	require.Contains(t, write.Description, "do not wait again")
	require.NotContains(t, write.Description, "repeat it")
	pending, ok := mcpcontract.Find(contracts, "list_pending")
	require.True(t, ok)
	require.Contains(t, pending.Description, "call write once, in the same turn, with its approvalId")
}

// TestArgsStructsMatchTheSchemas keeps each tool's Go argument struct and its
// contract's input properties in step.
func TestArgsStructsMatchTheSchemas(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"run_start": runStartArgs{}, "query": queryArgs{}, "write": writeArgs{}, "run_history": runHistoryArgs{}, "list_pending": listPendingArgs{},
		"list_runs":      ledger.RunListParams{},
		"request_revert": requestRevertArgs{},
		"preview_revert": previewRevertArgs{},
		"describe":       describeArgs{},
	}
	// Fields a struct decodes only to refuse them with a clear message: the
	// embedded pagination.Params brings sort, which preview_revert refuses
	// (its lines come in their signed order).
	refused := map[string][]string{"preview_revert": {"sort"}, "describe": {"sort"}}
	for name, v := range args {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		props, ok := c.InputSchema["properties"].(map[string]any)
		require.True(t, ok)
		want := make([]string, 0, len(props)+len(refused[name]))
		for p := range props {
			want = append(want, p)
		}
		want = append(want, refused[name]...)
		sort.Strings(want)
		require.Equal(t, want, jsonFields(v), name)
	}
}

func jsonFields(v any) []string {
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		f := rt.Field(i)
		if f.Anonymous { // an embedded struct (pagination.Params) adds its fields
			out = append(out, jsonFields(reflect.New(f.Type).Elem().Interface())...)
			continue
		}
		out = append(out, strings.Split(f.Tag.Get("json"), ",")[0])
	}
	sort.Strings(out)
	return out
}

func TestToolErrorMapping(t *testing.T) {
	t.Parallel()
	pg := func(code, msg string) error {
		return postgres.MapError(fmt.Errorf("exec: %w", &pgconn.PgError{Code: code, Message: msg}))
	}
	cases := []struct {
		err                    error
		code, reason, sqlState string
	}{
		{pg("BS001", "INTENT_REQUIRED: UPDATE on public.leads"), CodeIntentRequired, "", "BS001"},
		{pg("BS002", "APPROVAL_REQUIRED: 11 rows"), CodeApprovalRequired, "", "BS002"},
		{pg("BS003", "ROW_LIMIT_EXCEEDED"), CodeRowLimitExceeded, "", "BS003"},
		{pg("BS004", "STALE_READ"), CodeStaleRead, "", "BS004"},
		{pg("BS005", "APPROVAL_EXPIRED"), CodeApprovalExpired, "", "BS005"},
		{pg("BS005", "APPROVAL_INVALID: approval already used"), CodeApprovalInvalid, reasonBadSignature, "BS005"},
		{postgres.MapError(&pgconn.PgError{Code: "BS005", Message: "APPROVAL_INVALID", Detail: "approval already used"}), CodeApprovalInvalid, reasonAlreadyUsed, "BS005"},
		{pg("BS006", "PREVIEW_CANNOT_COMMIT"), CodeInternal, "", "BS006"},
		{pg("BS007", "NOT_ALLOWED: unknown basalt.mode"), CodeStatementRefused, ReasonNotAllowed, "BS007"},
		{pg("BS008", "LEDGER_INPUT_INVALID"), CodeInternal, "", "BS008"},
		{pg("57014", "canceling statement due to statement timeout"), CodeQueryTimeout, ReasonTimeLimit, "57014"},
		{pg("42501", "permission denied for table secrets"), CodePermissionDenied, "", "42501"},
		{pg("08006", "connection failure"), CodeUnavailable, reasonDatabaseUnreachable, "08006"},
		{pg("28P01", "password authentication failed"), CodeUnavailable, reasonCredentialRejected, "28P01"},
		{pg("57P01", "terminating connection due to administrator command"), CodeUnavailable, reasonDatabaseUnreachable, "57P01"},
		{pg("53300", `too many connections for role "basalt_agent_bot"`), CodeUnavailable, reasonTooManyConnections, "53300"},
		{pg("53100", "could not extend file: No space left on device"), CodeUnavailable, reasonDatabaseUnreachable, "53100"},
		{pg("23505", "duplicate key"), CodeSQLError, "", "23505"},
		{&action.RefusalError{Reason: action.ReasonDDL}, CodeStatementRefused, "DDL_NOT_ALLOWED", ""},
		{fmt.Errorf("read: %w", action.ErrRowLimit), CodeQueryTimeout, ReasonRowLimit, ""},
		{fmt.Errorf("read: %w", postgres.ErrSizeLimit), CodeQueryTimeout, ReasonSizeLimit, ""},
		{postgres.MapError(fmt.Errorf("read: %w", &pgproto3.ExceededMaxBodyLenErr{MaxExpectedBodyLen: 1, ActualBodyLen: 2})), CodeInternal, "", ""},
		{&ArgumentError{Message: "bad"}, CodeInvalidArgument, "", ""},
		{&mcp.ToolError{Code: CodeNotFound, Reason: reasonRun, Message: "no run"}, CodeNotFound, reasonRun, ""},
		{context.DeadlineExceeded, CodeUnavailable, reasonDatabaseUnreachable, ""},
		{fmt.Errorf("list: %w", ledger.ErrInvalidParams), CodeInvalidArgument, "", ""},
		{guard.ErrInvalidIntent, CodeInvalidArgument, "", ""},
		{fmt.Errorf("list: %w: invalid cursor: missing id", ledger.ErrInvalidParams), CodeInvalidArgument, ReasonStaleCursor, ""},
		{postgres.MapError(&pgconn.PgError{Code: "BS007", Message: "NOT_ALLOWED", Detail: "table public.t has no primary key"}), CodeStatementRefused, ReasonNoPrimaryKey, "BS007"},
		{errors.New("password=hunter2 something broke"), CodeInternal, "", ""},
	}
	for _, c := range cases {
		te := ToolError(c.err)
		require.Equal(t, c.code, te.Code, c.err.Error())
		require.Equal(t, c.reason, te.Reason, c.err.Error())
		require.Equal(t, c.sqlState, te.SQLState, c.err.Error())
		require.NotContains(t, te.Message, "hunter2")
	}
}

func TestNewServicePanicsWithoutDeps(t *testing.T) {
	t.Parallel()
	for _, breakIt := range []func(*Deps){
		func(d *Deps) { d.Name = "" },
		func(d *Deps) { d.Store = nil },
		func(d *Deps) { d.Log = nil },
		func(d *Deps) { d.Now = nil },
	} {
		d := deps()
		breakIt(&d)
		require.Panics(t, func() { NewService(d) })
	}
	require.Panics(t, func() { Tools(nil) })
}

func TestTruncateKeepsRunes(t *testing.T) {
	t.Parallel()
	require.Equal(t, "abc", truncate("abc", 5))
	require.Equal(t, "ab", truncate("abé", 3), "never cut inside a rune")
	require.Equal(t, "abé", truncate("abé", 4))
}

// An INTERNAL or UNAVAILABLE error carries a UUIDv7 errorId that the engine
// logs with the error, so the person can find the log line.
func TestErrorIDIsInTheBodyAndTheLogLine(t *testing.T) {
	t.Parallel()
	for name, cause := range map[string]error{
		CodeInternal:    errors.New("boom"),
		CodeUnavailable: context.DeadlineExceeded,
	} {
		var logged strings.Builder
		d := deps()
		d.Log = slog.New(slog.NewTextHandler(&logged, nil))
		h := handlers{svc: NewService(d)}
		call := h.wrap("query", func(context.Context, json.RawMessage) (any, error) { return nil, cause })

		_, err := call(context.Background(), nil)
		var te *mcp.ToolError
		require.True(t, errors.As(err, &te), name)
		require.Equal(t, name, te.Code)
		id, perr := uuid.Parse(te.ErrorID)
		require.NoError(t, perr, "%s: %q", name, te.ErrorID)
		require.Equal(t, uuid.Version(7), id.Version(), name)
		require.Contains(t, logged.String(), "error_id="+te.ErrorID, name)

		body, merr := json.Marshal(te)
		require.NoError(t, merr)
		require.Contains(t, string(body), `"errorId":"`+te.ErrorID+`"`, name)
	}
}

func TestErrorIDOnlyOnInternalAndUnavailable(t *testing.T) {
	t.Parallel()
	h := handlers{svc: NewService(deps())}
	call := h.wrap("query", func(context.Context, json.RawMessage) (any, error) { return nil, &ArgumentError{Message: "bad"} })
	_, err := call(context.Background(), nil)
	var te *mcp.ToolError
	require.True(t, errors.As(err, &te))
	require.Empty(t, te.ErrorID)
}
