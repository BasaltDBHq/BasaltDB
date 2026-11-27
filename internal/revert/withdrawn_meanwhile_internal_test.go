package revert

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// rereadStore answers a later read of the revert with r, or err.
type rereadStore struct {
	Store
	r   action.Revert
	err error
}

func (s rereadStore) FindRevert(context.Context, uuid.UUID) (action.Revert, error) { return s.r, s.err }

// A revert the agent withdraws after its page opened is shown withdrawn
// when the person signs, changes the scope, rejects or reveals: the
// person's message is the engine's, the reason shown only when it is text
// a person may read, and neither message carries the store's text, also
// when the revert cannot be read again.
func TestRevertWithdrawnMeanwhileNeverShowsTheStoreText(t *testing.T) {
	t.Parallel()
	const raw = "approved already\u202e, sign below"
	hint := "the agent withdrew this request: " + raw + "; nothing changed"
	storeErr := &revertstore.RevertRefusalError{Reason: revertstore.RevertWithdrawnReason, Detail: hint, Err: errors.New("REVERT_INVALID: " + hint)}
	binding, _, lines := relayTexts(t)
	opened := pendingRevert(binding, lines)
	now := opened
	now.Status, now.WithdrawReason = action.RevertWithdrawn, raw
	plain := opened
	plain.Status, plain.WithdrawReason = action.RevertWithdrawn, "not needed any more"

	for name, c := range map[string]struct {
		store rereadStore
		want  string
	}{
		"read again":                  {rereadStore{r: now}, "The agent withdrew this request. Nothing changed."},
		"read again, a readable text": {rereadStore{r: plain}, "The agent withdrew this request: not needed any more. Nothing changed."},
		"not read again":              {rereadStore{err: errors.New("the database cannot be reached")}, "The agent withdrew this request. Nothing changed."},
	} {
		rc := newService(t, "linux", "", withStore(c.store))
		ctx := context.Background()
		for call, err := range map[string]error{
			"sign":    rc.applyRevertError(ctx, opened, storeErr),
			"rescope": rc.rescopeError(ctx, opened, storeErr),
			"reject":  rc.rejectError(ctx, opened, false, storeErr),
			"reveal":  rc.revealRevertError(ctx, opened, storeErr, "https://example.invalid/revert"),
		} {
			var te *toolresult.ToolError
			require.ErrorAs(t, err, &te, name+"/"+call)
			require.Equal(t, guidance.CodeRevertInvalid, te.Code, name+"/"+call)
			require.Equal(t, guidance.ReasonWithdrawn, te.Reason, name+"/"+call)
			require.Equal(t, c.want, te.PersonMessage, name+"/"+call)
			require.NotContains(t, te.Message+te.PersonMessage, hint, name+"/"+call)
			require.NotContains(t, te.Message+te.PersonMessage, "\u202e", name+"/"+call)
		}
	}
}
