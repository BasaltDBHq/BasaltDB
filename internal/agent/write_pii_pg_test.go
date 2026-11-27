package agent_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// refusingObserver cannot add any value. It records whether a write's
// returned rows came with classes read alone, inside the write's
// transaction.
type refusingObserver struct{ inTx *bool }

func (refusingObserver) Observe(context.Context, []action.Column, []map[string]any) error {
	return errors.New("pii: dictionary delta is full")
}

func (o refusingObserver) ObserveReturned(_ context.Context, classes pii.Classes, _ []action.Column, _ []map[string]any) error {
	*o.inTx = !classes.Shared()
	return corepii.ErrDeltaFull
}

// piiWriteService is the write use case over a real database whose people
// table has its email column classified IDENTIFIER, writing through a store
// whose RETURNING rows go to obs inside the write's transaction.
func piiWriteService(t *testing.T, obs agent.PIIObserver) (*agent.Service, *guardtest.DB) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, email text, city text);
		INSERT INTO public.people VALUES (1, 'ann@corp.ee', 'Tartu'), (2, 'ben@corp.ee', 'Narva');`)
	a := d.NewAgent(t, "bot", []string{"public.people"}, nil)
	rows, err := d.Admin.Query(context.Background(), `SELECT table_schema, table_name, column_name, data_type FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guardmodel.PIIColumn, error) {
		var c guardmodel.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guardmodel.ClassPublic
		if c.Column == "email" {
			c.Class, c.EntityType = guardmodel.ClassIdentifier, guardmodel.EntityEmail
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(context.Background(), d.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(context.Background(), tx, d.Names, guardmodel.Classification{Columns: cols, At: time.Now()})
	}))
	pool, _, err := postgres.NewSwitchablePool(context.Background(), a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	store := postgres.NewStore(resultsize.Pool(pool), action.DefaultLimits(), time.Now)
	core := agent.Core{Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now, Errors: pgerrors.Map()}
	set := agent.StoreSet{
		Kind: store.Kind(), Family: agentstore.FamilySQL, Capabilities: store.Capabilities(),
		Language: sqllang.New(store), Data: pgData{store}, Ledger: store,
	}
	return agent.New(core, set, obs, func() *guidance.UpdateInfo { return nil }, nil, nil, nil, nil, nil), d
}

// pgData is the Postgres store as the agent's writes run on it.
type pgData struct{ *postgres.Store }

func (p pgData) Read(ctx context.Context, req agentstore.Request, stmt action.Statement) (action.ReadResult, error) {
	return p.Store.Read(ctx, req.Text, req.Params, stmt)
}

func (p pgData) Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	return p.Store.Write(ctx, in, stmt.Op, req.Text, req.Params, txReturned(returned))
}

func (p pgData) WriteApproved(ctx context.Context, in action.Intent, id uuid.UUID, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	return p.Store.WriteApproved(ctx, in, id, stmt.Op, req.Text, req.Params, txReturned(returned))
}

// txReturned reads the classes on the write's own transaction, as
// internal/app wires it.
func txReturned(returned agent.Returned) postgres.Returned {
	return func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error {
		return returned(ctx, pgpii.ClassesInTx(pgquerier.Unwrap(tx)), cols, rows)
	}
}

func (pgData) Limits() action.Limits { return action.DefaultLimits() }

func TestWriteRollsBackWhenItsReturnedValuesCannotBeAdded(t *testing.T) {
	t.Parallel()
	var inTx bool
	svc, d := piiWriteService(t, refusingObserver{inTx: &inTx})
	_, err := svc.Write(context.Background(), agent.WriteParams{
		Request: agentstore.Request{Text: `UPDATE people SET city = 'Pärnu' WHERE id = 1 RETURNING email`}, Intent: "move ann",
	})
	require.ErrorIs(t, err, corepii.ErrDeltaFull)
	require.True(t, inTx, "the PII port reads the classes inside the write's transaction")
	var city string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT city FROM people WHERE id = 1`).Scan(&city))
	require.Equal(t, "Tartu", city, "the write was rolled back")
}
