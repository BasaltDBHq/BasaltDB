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

	"github.com/basaltdbhq/basaltdb/internal/approval/in/approvalmcp"
	"github.com/basaltdbhq/basaltdb/internal/ledger/in/ledgermcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin/in/pluginmcp"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
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
func (nopStore) History(context.Context, action.ChangeListParams) (History, error) {
	return History{}, nil
}

func (nopStore) ListRuns(context.Context, action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return pagination.Page[action.RunSummary]{}, nil
}

func deps() Deps {
	d := testDeps()
	d.Core.Name, d.Core.Log, d.Core.Now = "bot", slog.New(slog.DiscardHandler), time.Now
	useStore(&d, parts{
		reader: nopReader{}, runStore: nopStore{}, readRecorder: nopRecorder{},
		approvalStore: struct{ approvalStore }{}, // never called by these tests
		Store:         struct{ revertsvc.Store }{},
	})
	return d
}

// servedTools are s's tools as the engine lists them (app's agentTools,
// whose tests pin the list and its order): each group's tools under their
// contracts, around s.Wrap. It copies app's composer: a layer app adds
// around Wrap, or a group it adds or reorders, must be added here too.
func servedTools(s *Service) []guidance.Tool {
	mount := func(name string, call func(context.Context, json.RawMessage) (any, error)) guidance.Tool {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		if !ok {
			panic("no contract for tool " + name)
		}
		return guidance.Tool{Name: c.Name, Description: c.Description, InputSchema: c.InputSchema, Call: s.Wrap(name, call)}
	}
	tools := RunStartTools(s, mount)
	for _, list := range [][]guidance.Tool{
		WriteTools(s, mount), ledgermcp.Tools(s, mount), RunTools(s, mount), approvalmcp.Tools(s, mount), revertmcp.Tools(s, mount),
		pluginmcp.Tools(s, mount), DescribeTools(s, mount), StatusTools(s, mount),
	} {
		tools = append(tools, list...)
	}
	return tools
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
		"run_start": runStartArgs{}, "query": queryArgs{}, "write": writeArgs{},
		"list_runs": action.RunListParams{},
		"describe":  describeArgs{},
	}
	// Fields a struct decodes only to refuse them with a clear message: the
	// embedded pagination.Params brings sort, which describe refuses.
	refused := map[string][]string{"describe": {"sort"}}
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
		return store.MapError(fmt.Errorf("exec: %w", &pgconn.PgError{Code: code, Message: msg}))
	}
	cases := []struct {
		err                    error
		code, reason, sqlState string
	}{
		{pg("BS001", "INTENT_REQUIRED: UPDATE on public.leads"), guidance.CodeIntentRequired, "", "BS001"},
		{pg("BS002", "APPROVAL_REQUIRED: 11 rows"), guidance.CodeApprovalRequired, "", "BS002"},
		{pg("BS003", "ROW_LIMIT_EXCEEDED"), guidance.CodeRowLimitExceeded, "", "BS003"},
		{pg("BS004", "STALE_READ"), guidance.CodeStaleRead, "", "BS004"},
		{pg("BS005", "APPROVAL_EXPIRED"), guidance.CodeApprovalExpired, "", "BS005"},
		{pg("BS005", "APPROVAL_INVALID: approval already used"), guidance.CodeApprovalInvalid, guidance.ReasonBadSignature, "BS005"},
		{store.MapError(&pgconn.PgError{Code: "BS005", Message: "APPROVAL_INVALID", Detail: "approval already used"}), guidance.CodeApprovalInvalid, guidance.ReasonAlreadyUsed, "BS005"},
		{pg("BS006", "PREVIEW_CANNOT_COMMIT"), guidance.CodeInternal, "", "BS006"},
		{pg("BS007", "NOT_ALLOWED: unknown basalt.mode"), guidance.CodeStatementRefused, guidance.ReasonNotAllowed, "BS007"},
		{pg("BS008", "LEDGER_INPUT_INVALID"), guidance.CodeInternal, "", "BS008"},
		{pg("57014", "canceling statement due to statement timeout"), guidance.CodeQueryTimeout, guidance.ReasonTimeLimit, "57014"},
		{pg("42501", "permission denied for table secrets"), guidance.CodePermissionDenied, "", "42501"},
		{pg("08006", "connection failure"), guidance.CodeUnavailable, guidance.ReasonDatabaseUnreachable, "08006"},
		{pg("28P01", "password authentication failed"), guidance.CodeUnavailable, guidance.ReasonCredentialRejected, "28P01"},
		{pg("57P01", "terminating connection due to administrator command"), guidance.CodeUnavailable, guidance.ReasonDatabaseUnreachable, "57P01"},
		{pg("53300", `too many connections for role "basalt_agent_bot"`), guidance.CodeUnavailable, guidance.ReasonTooManyConnections, "53300"},
		{pg("53100", "could not extend file: No space left on device"), guidance.CodeUnavailable, guidance.ReasonDatabaseUnreachable, "53100"},
		{pg("23505", "duplicate key"), guidance.CodeSQLError, "", "23505"},
		{&action.RefusalError{Reason: action.ReasonDDL}, guidance.CodeStatementRefused, "DDL_NOT_ALLOWED", ""},
		{fmt.Errorf("read: %w", action.ErrRowLimit), guidance.CodeQueryTimeout, guidance.ReasonRowLimit, ""},
		{fmt.Errorf("read: %w", budget.ErrSizeLimit), guidance.CodeQueryTimeout, guidance.ReasonSizeLimit, ""},
		{store.MapError(fmt.Errorf("read: %w", &pgproto3.ExceededMaxBodyLenErr{MaxExpectedBodyLen: 1, ActualBodyLen: 2})), guidance.CodeInternal, "", ""},
		{&guidance.ArgumentError{Message: "bad"}, guidance.CodeInvalidArgument, "", ""},
		{&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: guidance.ReasonRun, Message: "no run"}, guidance.CodeNotFound, guidance.ReasonRun, ""},
		{context.DeadlineExceeded, guidance.CodeUnavailable, guidance.ReasonDatabaseUnreachable, ""},
		{fmt.Errorf("list: %w", ledger.ErrInvalidParams), guidance.CodeInvalidArgument, "", ""},
		{guard.ErrInvalidIntent, guidance.CodeInvalidArgument, "", ""},
		{fmt.Errorf("list: %w: invalid cursor: missing id", ledger.ErrInvalidParams), guidance.CodeInvalidArgument, guidance.ReasonStaleCursor, ""},
		{store.MapError(&pgconn.PgError{Code: "BS007", Message: "NOT_ALLOWED", Detail: "table public.t has no primary key"}), guidance.CodeStatementRefused, guidance.ReasonNoPrimaryKey, "BS007"},
		{errors.New("password=hunter2 something broke"), guidance.CodeInternal, "", ""},
	}
	for _, c := range cases {
		te := testErrors().ToolError(c.err)
		require.Equal(t, c.code, te.Code, c.err.Error())
		require.Equal(t, c.reason, te.Reason, c.err.Error())
		require.Equal(t, c.sqlState, te.SQLState, c.err.Error())
		require.NotContains(t, te.Message, "hunter2")
	}
}

func TestNewServicePanicsWithoutDeps(t *testing.T) {
	t.Parallel()
	for name, breakIt := range map[string]func(*Deps){
		"Core.Name":                     func(d *Deps) { d.Core.Name = "" },
		"Core.Store":                    func(d *Deps) { d.Core.Store = nil },
		"Core.Log":                      func(d *Deps) { d.Core.Log = nil },
		"Core.Now":                      func(d *Deps) { d.Core.Now = nil },
		"Core.ServiceManager":           func(d *Deps) { d.Core.ServiceManager = guidance.ServiceManager{} },
		"Core.Errors.InvalidParams":     func(d *Deps) { d.Core.Errors.InvalidParams = nil },
		"Core.Errors.InvalidIntent":     func(d *Deps) { d.Core.Errors.InvalidIntent = nil },
		"Core.Errors.RowTooLarge":       func(d *Deps) { d.Core.Errors.RowTooLarge = nil },
		"Write.Store":                   func(d *Deps) { d.Write.Store = nil },
		"Write.Record":                  func(d *Deps) { d.Write.Record = nil },
		"Approval.Store":                func(d *Deps) { d.Approval.Store = nil },
		"Approval.ErrNotFound":          func(d *Deps) { d.Approval.ErrNotFound = nil },
		"Revert.Store":                  func(d *Deps) { d.Revert.Store = nil },
		"Revert.ErrNotFound":            func(d *Deps) { d.Revert.ErrNotFound = nil },
		"Revert.AfterAnswer":            func(d *Deps) { d.Revert.AfterAnswer = nil },
		"Revert.RotateSession":          func(d *Deps) { d.Revert.RotateSession = nil },
		"Delivery.VaultConflict":        func(d *Deps) { d.Delivery.VaultConflict = nil },
		"Delivery.ErrVaultNotConnected": func(d *Deps) { d.Delivery.ErrVaultNotConnected = nil },
		"Status.Passkeys":               func(d *Deps) { d.Status.Passkeys = nil },
		"Status.CrashReports":           func(d *Deps) { d.Status.CrashReports = nil },
		"Status.LatestGuardVersion":     func(d *Deps) { d.Status.LatestGuardVersion = nil },
		"Status.UpdateMessage":          func(d *Deps) { d.Status.UpdateMessage = nil },
		"Status.StartHoldOffUntil":      func(d *Deps) { d.Status.StartHoldOffUntil = nil },
	} {
		d := deps()
		breakIt(&d)
		require.PanicsWithValue(t, "agent: required dependencies missing: "+name, func() { NewService(d) }, name)
	}
	require.NotPanics(t, func() { NewService(deps()) })
}

// An INTERNAL or UNAVAILABLE error carries a UUIDv7 errorId that the engine
// logs with the error, so the person can find the log line.
func TestErrorIDIsInTheBodyAndTheLogLine(t *testing.T) {
	t.Parallel()
	for name, cause := range map[string]error{
		guidance.CodeInternal:    errors.New("boom"),
		guidance.CodeUnavailable: context.DeadlineExceeded,
	} {
		var logged strings.Builder
		d := deps()
		d.Core.Log = slog.New(slog.NewTextHandler(&logged, nil))
		h := handlers{svc: NewService(d)}
		call := h.wrap("query", func(context.Context, json.RawMessage) (any, error) { return nil, cause })

		_, err := call(context.Background(), nil)
		var te *toolresult.ToolError
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
	call := h.wrap("query", func(context.Context, json.RawMessage) (any, error) {
		return nil, &guidance.ArgumentError{Message: "bad"}
	})
	_, err := call(context.Background(), nil)
	var te *toolresult.ToolError
	require.True(t, errors.As(err, &te))
	require.Empty(t, te.ErrorID)
}
