package upkeep_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/service/upkeep"
)

// noDB fails the test on any statement: a gated tick must not reach the
// database.
type noDB struct{ t *testing.T }

func (d noDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	d.t.Error("a refused tick ran a statement")
	return pgconn.CommandTag{}, errors.New("no database")
}

func (d noDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	d.t.Error("a refused tick ran a query")
	return nil, errors.New("no database")
}

func (d noDB) QueryRow(context.Context, string, ...any) pgx.Row {
	d.t.Error("a refused tick ran a query")
	return nil
}

// savedPins records every pin.
type savedPins struct{ saved int }

func (p *savedPins) Load(string) (chainpin.Pin, bool, error) { return chainpin.Pin{}, false, nil }

func (p *savedPins) Save(string, chainpin.Pin) error {
	p.saved++
	return nil
}

func TestATickTheGuardRefusesDoesNothing(t *testing.T) {
	t.Parallel()
	pins := &savedPins{}
	refuse := errors.New("the guard misses breaking migrations 18")
	u := upkeep.New("bot", "test", store.NewUpkeep(noDB{t: t}), slog.New(slog.DiscardHandler), time.Now).
		WithPins(pins).WithGate(func(context.Context) error { return refuse })
	err := u.Tick(context.Background())
	require.ErrorIs(t, err, refuse)
	require.Contains(t, err.Error(), "skipped")
	require.Zero(t, pins.saved, "no chain head is pinned from a schema the engine does not serve")
}

// The engine and basalt log agree on how long a silence is.
func TestDeadManAfterMatchesTheLedger(t *testing.T) {
	t.Parallel()
	require.Equal(t, ledger.DeadManAfter, upkeep.DeadManAfter)
}
