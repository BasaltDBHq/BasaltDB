package pii

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// A full pool must not wedge the agent: writes through the store that hold
// every connection and meet an unknown table reload the map on their own
// transaction, with ticks, scans and reads running at once on a
// two-connection pool.
func TestConcurrentUnknownOIDWritesOnAFullPool(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, _, err := postgres.NewSwitchablePool(ctx, f.agent.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	dict, _ := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	classes := NewMap(slog.New(slog.DiscardHandler))
	obs := NewObserver(classes, dict)
	store := postgres.NewStore(pool, sqlguard.DefaultLimits(), time.Now)
	reader := postgres.NewReader(pool, sqlguard.DefaultLimits(), time.Now)
	scan := NewScanner(dict, []ScanSource{{Agent: "bot", Map: classes, Classes: pgpii.Classes(pool), Fields: pgpii.Fields(pool, sqlguard.DefaultLimits(), DefaultLoadTimeout)}},
		ScanOptions{}, slog.New(slog.DiscardHandler))
	in := action.Intent{RunID: uuidV7(t), TaskID: uuidV7(t), Text: "touch customers"}
	require.NoError(t, store.StartRun(ctx, in))

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	report := func(err error) {
		if err != nil {
			errs <- err
		}
	}
	for _, id := range []int{1, 2, 3} {
		wg.Go(func() {
			for range 4 {
				// p.label comes from plain, a table with no classes.
				_, err := store.Write(ctx, in, action.OpUpdate,
					`UPDATE customers c SET note = 'n' FROM plain p WHERE c.id = $1 AND p.id = 1 RETURNING c.email, p.label`, []any{id}, returned(obs))
				report(err)
			}
		})
	}
	wg.Go(func() {
		for range 4 {
			_, err := classes.Tick(ctx, pgpii.Classes(pool))
			report(err)
		}
	})
	wg.Go(func() {
		for range 2 {
			_, err := scan.Cycle(ctx)
			report(err)
		}
	})
	wg.Go(func() {
		for range 4 {
			res, err := reader.Read(ctx, `SELECT label FROM plain`, nil, action.Statement{})
			if err == nil {
				err = obs.Observe(ctx, pgpii.Classes(pool), resultFields(res.Columns), res.Rows)
			}
			report(err)
		}
	})
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestDictionaryErrorsAreEngineErrors(t *testing.T) {
	t.Parallel()
	err := error(&DictionaryError{err: &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}})
	var pe *pgconn.PgError
	require.False(t, errors.As(err, &pe), "a map reload's Postgres error is not the agent's SQL error")
	err = &DictionaryError{err: corepii.ErrDeltaFull}
	require.ErrorIs(t, err, corepii.ErrDeltaFull)
}
