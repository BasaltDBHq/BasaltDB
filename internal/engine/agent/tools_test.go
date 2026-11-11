package agent

import (
	"context"
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
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

type nopReader struct{}

func (nopReader) Read(context.Context, string, []any, []sqlguard.RowSource) (agentdb.ReadResult, error) {
	return agentdb.ReadResult{}, nil
}

type nopRecorder struct{}

func (nopRecorder) RecordRead(context.Context, guard.Read) (uuid.UUID, error) { return uuid.Nil, nil }

type nopStore struct{}

func (nopStore) FindRun(context.Context, uuid.UUID) (agentdb.Run, error) { return agentdb.Run{}, nil }
func (nopStore) StartRun(context.Context, guard.Intent) error            { return nil }
func (nopStore) Write(context.Context, guard.Intent, sqlguard.Op, string, []any) (agentdb.WriteResult, error) {
	return agentdb.WriteResult{}, nil
}
func (nopStore) RecordRefusal(context.Context, guard.Refusal) error { return nil }
func (nopStore) History(context.Context, ledger.ChangeListParams) (agentdb.History, error) {
	return agentdb.History{}, nil
}

func deps() Deps {
	return Deps{
		Name: "bot", Reader: nopReader{}, Store: nopStore{}, Reads: nopRecorder{},
		Approvals: struct{ ApprovalStore }{}, // never called by these tests
		Reverts:   struct{ RevertStore }{},
		Log:       slog.New(slog.DiscardHandler), Now: time.Now,
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
		"request_revert": requestRevertArgs{},
	}
	for name, v := range args {
		c, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok)
		props, ok := c.InputSchema["properties"].(map[string]any)
		require.True(t, ok)
		want := make([]string, 0, len(props))
		for p := range props {
			want = append(want, p)
		}
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
	pg := func(code, msg string) error { return fmt.Errorf("exec: %w", &pgconn.PgError{Code: code, Message: msg}) }
	cases := []struct {
		err                    error
		code, reason, sqlState string
	}{
		{pg("BS001", "INTENT_REQUIRED: UPDATE on public.leads"), CodeIntentRequired, "", "BS001"},
		{pg("BS002", "APPROVAL_REQUIRED: 11 rows"), CodeApprovalRequired, "", "BS002"},
		{pg("BS003", "ROW_LIMIT_EXCEEDED"), CodeRowLimitExceeded, "", "BS003"},
		{pg("BS004", "STALE_READ"), CodeStaleRead, "", "BS004"},
		{pg("BS005", "APPROVAL_EXPIRED"), CodeApprovalExpired, "", "BS005"},
		{pg("BS005", "APPROVAL_INVALID: approval already used"), CodeApprovalInvalid, "", "BS005"},
		{pg("BS006", "PREVIEW_CANNOT_COMMIT"), CodeInternal, "", "BS006"},
		{pg("BS007", "NOT_ALLOWED: unknown basalt.mode"), CodeStatementRefused, "", "BS007"},
		{pg("BS008", "LEDGER_INPUT_INVALID"), CodeInternal, "", "BS008"},
		{pg("57014", "canceling statement due to statement timeout"), CodeQueryTimeout, ReasonTimeLimit, "57014"},
		{pg("42501", "permission denied for table secrets"), CodePermissionDenied, "", "42501"},
		{pg("08006", "connection failure"), CodeUnavailable, "", "08006"},
		{pg("28P01", "password authentication failed"), CodeUnavailable, "", "28P01"},
		{pg("57P01", "terminating connection due to administrator command"), CodeUnavailable, "", "57P01"},
		{pg("23505", "duplicate key"), CodeSQLError, "", "23505"},
		{&sqlguard.RefusalError{Reason: sqlguard.ReasonDDL}, CodeStatementRefused, "DDL_NOT_ALLOWED", ""},
		{fmt.Errorf("read: %w", agentdb.ErrRowLimit), CodeQueryTimeout, ReasonRowLimit, ""},
		{&ArgumentError{Message: "bad"}, CodeInvalidArgument, "", ""},
		{&mcp.ToolError{Code: CodeNotFound, Message: "no run"}, CodeNotFound, "", ""},
		{context.DeadlineExceeded, CodeUnavailable, "", ""},
		{fmt.Errorf("list: %w", ledger.ErrInvalidParams), CodeInvalidArgument, "", ""},
		{guard.ErrInvalidIntent, CodeInvalidArgument, "", ""},
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
		func(d *Deps) { d.Reader = nil },
		func(d *Deps) { d.Store = nil },
		func(d *Deps) { d.Reads = nil },
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
