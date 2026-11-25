package revert_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	corerevert "github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// countedFinds counts the reads of a revert, so a test knows the wait polls.
type countedFinds struct {
	revert.Store
	n atomic.Int64
}

func (c *countedFinds) FindRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	c.n.Add(1)
	return c.Store.FindRevert(ctx, id)
}

// A canceled call stops waiting at once.
func TestRequestRevertWaitCancelled(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, []string{"public.leads"})
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Mark leads won"}
	require.NoError(t, guard.StartRun(ctx, a.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 86`))
	prep, err := guard.PrepareRevert(ctx, a.Conn, action.Scope{Kind: corerevert.ScopeRun, ID: in.RunID}, "Undo")
	require.NoError(t, err)

	// The revert use case as the engine runs its wait: the agent's store,
	// and the delivery's poll loop.
	pool, err := postgres.NewPool(ctx, a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	finds := &countedFinds{Store: postgres.NewStore(resultsize.Pool(pool), sqlguard.DefaultLimits(), time.Now)}
	delivery := linksvc.New(linksvc.Core{Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now}, &linksvc.Deps{Poll: 10 * time.Millisecond}, nil, nil)
	rc := revert.New(revert.Core{Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now}, revert.StoreSet{Records: finds, Undo: finds, Proofs: finds}, &revert.Deps{ErrNotFound: ledger.ErrRevertNotFound}, nil, delivery, nil, nil)

	waitCtx, cancel := context.WithCancel(ctx)
	go func() {
		// Cancel once the wait has read the revert and polled it once.
		deadline := time.Now().Add(10 * time.Second)
		for finds.n.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	_, err = rc.AwaitRevert(waitCtx, revert.AwaitRevertParams{RevertID: prep.RevertID, Wait: revert.DefaultRevertWait})
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 5*time.Second)
}
