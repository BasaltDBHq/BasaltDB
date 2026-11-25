package approval

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// holdStore answers a hold's preview and hold with fixed results, and keeps
// what the service sent it.
type holdStore struct {
	catalogStore
	preview    action.HeldPreview
	previewErr error
	holdErr    error

	previewed []agentstore.Request
	held      []action.HoldRequest
}

func (s *holdStore) Preview(_ context.Context, _ action.Intent, req agentstore.Request) (action.HeldPreview, error) {
	s.previewed = append(s.previewed, req)
	return s.preview, s.previewErr
}

func (s *holdStore) Hold(_ context.Context, _ action.Intent, r action.HoldRequest) (action.Held, error) {
	s.held = append(s.held, r)
	if s.holdErr != nil {
		return action.Held{}, s.holdErr
	}
	return action.Held{ApprovalID: uuid.Must(uuid.NewV7()), BindingText: "binding"}, nil
}

// The service previews through the store, checks the lines and holds with
// the request as the agent sent it, Basalt's op and the preview's fields.
func TestHoldPassesTheRequestOnUnread(t *testing.T) {
	t.Parallel()
	st := &holdStore{preview: action.HeldPreview{Assigned: []string{"status"}, Lines: []string{`{"op":"UPDATE"}`}}}
	ac := newService(t, "linux", "", func(s *settings) { s.store = st })
	req := agentstore.Request{Text: `{"filter": {"status": "open"}}`, Params: []any{1}}

	held, err := ac.Hold(context.Background(), action.Intent{Text: "close"}, req, action.OpUpdate)
	require.NoError(t, err)
	require.Equal(t, []agentstore.Request{req}, st.previewed)
	require.Equal(t, []action.HoldRequest{{Op: action.OpUpdate, Request: req, Assigned: []string{"status"}, Lines: st.preview.Lines}}, st.held)
	require.Equal(t, st.preview.Lines, held.Lines)
	require.Equal(t, "binding", held.BindingText)
}

// Each way a hold can fail keeps its answer, and only the refusals the agent
// records come as a *HoldRefusalError.
func TestHoldExits(t *testing.T) {
	t.Parallel()
	notRepeatable := &action.RefusalError{Reason: action.ReasonNotRepeatable, Detail: "now() gives another value"}
	catalog := errors.New("catalog read failed")
	run := &action.StoreError{Code: guidance.CodeStoreError, Message: "the preview failed"}
	olderGuard := &action.StoreError{Code: guidance.CodeStoreError, Message: "each line must be the jsonb text of a preview line"}
	guardTooLarge := &toolresult.ToolError{Code: guidance.CodeStatementRefused, Reason: action.ReasonHoldTooLarge, Message: "the guard refused the lines"}
	line := []string{"x"}
	over := []string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes+1)}
	for _, tc := range []struct {
		name    string
		store   holdStore
		want    error // the answer, compared with errors.Is
		code    string
		refusal bool // a *HoldRefusalError: the agent records it
		holds   int  // calls to the store's Hold
	}{
		{name: "not repeatable", store: holdStore{previewErr: notRepeatable}, want: notRepeatable, refusal: true},
		{name: "catalog read failing", store: holdStore{previewErr: catalog}, want: catalog},
		{name: "preview run failing", store: holdStore{previewErr: &action.PreviewFailedError{Err: run}}, want: run, refusal: true},
		{name: "no rows now", store: holdStore{preview: action.HeldPreview{Lines: nil}}, code: guidance.CodeStoreError},
		{name: "over the cap", store: holdStore{preview: action.HeldPreview{Lines: over}}, code: guidance.CodeStatementRefused, refusal: true},
		// Unreachable in practice: admission refuses a guard from before the
		// 64 MiB cap (64 KiB a line) before any hold. Not a regression.
		{name: "the hold failing on a long line", store: holdStore{preview: action.HeldPreview{Lines: []string{strings.Repeat("x", 64<<10+1)}}, holdErr: olderGuard}, want: olderGuard, holds: 1},
		{name: "the guard's own cap", store: holdStore{preview: action.HeldPreview{Lines: line}, holdErr: guardTooLarge}, want: guardTooLarge, holds: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := tc.store
			ac := newService(t, "linux", "", func(s *settings) { s.store = &st })
			_, err := ac.Hold(context.Background(), action.Intent{}, agentstore.Request{Text: "w"}, action.OpDelete)
			require.Error(t, err)
			var refusal *HoldRefusalError
			require.Equal(t, tc.refusal, errors.As(err, &refusal), "recorded by the agent")
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				if refusal != nil {
					require.Same(t, tc.want, refusal.Err, "the answer itself, never the store's marker")
				} else {
					require.Same(t, tc.want, err, "returned as it is")
				}
			}
			if tc.code != "" {
				var te *toolresult.ToolError
				require.ErrorAs(t, err, &te)
				require.Equal(t, tc.code, te.Code)
			}
			require.Len(t, st.held, tc.holds)
		})
	}
}
