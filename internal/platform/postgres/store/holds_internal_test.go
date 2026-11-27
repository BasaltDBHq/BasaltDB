package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
)

// failingDB fails every query and every transaction with its own error.
type failingDB struct {
	query, begin error
}

func (db failingDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, db.query
}

func (db failingDB) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, db.query }

func (db failingDB) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (db failingDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) { return nil, db.begin }

// Preview tells its failures apart the way the hold records them: a write
// that cannot be run again is a refusal, the catalog read's and the time
// evaluation's errors come unmarked, and an error of the preview run is
// marked PreviewFailedError.
func TestPreviewMarksOnlyThePreviewRun(t *testing.T) {
	t.Parallel()
	catalog, begin := errors.New("catalog read failed"), errors.New("preview failed")
	s := NewStore(failingDB{query: catalog, begin: begin}, action.DefaultLimits(), time.Now)
	ctx := context.Background()

	_, err := s.Preview(ctx, action.Intent{}, agentstore.Request{Text: "UPDATE public.leads SET n = random()"})
	var re *action.RefusalError
	require.ErrorAs(t, err, &re)
	require.Equal(t, action.ReasonNotRepeatable, re.Reason)
	require.Contains(t, re.Detail, "random()")
	var pf *approvalstore.PreviewFailedError
	require.False(t, errors.As(err, &pf))

	_, err = s.Preview(ctx, action.Intent{}, agentstore.Request{Text: "UPDATE public.leads SET at = now()"})
	require.Error(t, err)
	require.False(t, errors.As(err, &pf), "fixing the time is not the preview run")
	require.False(t, errors.As(err, &re))

	_, err = s.Preview(ctx, action.Intent{}, agentstore.Request{Text: "INSERT INTO public.leads VALUES (1)"})
	require.Error(t, err)
	require.False(t, errors.As(err, &pf), "the catalog read is not the preview run")
	require.False(t, errors.As(err, &re))

	_, err = s.Preview(ctx, action.Intent{}, agentstore.Request{Text: "DELETE FROM public.leads WHERE id = $1", Params: []any{1}})
	require.ErrorAs(t, err, &pf)
	require.Equal(t, MapError(begin).Error(), pf.Error(), "reads as the mapped error")
}
