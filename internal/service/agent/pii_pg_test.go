package agent_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/piidict"
)

// piiService is the engine's agent service with the PII observer wired as
// the engine wires it: query rows through the service, RETURNING rows inside
// the write's transaction.
func piiService(t *testing.T, obs agent.PIIObserver, returned store.ReturnedFunc) (*agent.Service, *guardtest.DB, *pii.FuseDictionary, *pii.Keys) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.people (id bigint PRIMARY KEY, email text, city text);
		INSERT INTO public.people VALUES (1, 'ann@corp.ee', 'Tartu'), (2, 'ben@corp.ee', 'Narva');`)
	a := d.NewAgent(t, "bot", []string{"public.people"}, nil)
	rows, err := d.Admin.Query(context.Background(), `SELECT table_schema, table_name, column_name, data_type FROM basalt_meta.pii_readable_columns()`)
	require.NoError(t, err)
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (guard.PIIColumn, error) {
		var c guard.PIIColumn
		err := r.Scan(&c.Schema, &c.Table, &c.Column, &c.DataType)
		c.Class = guard.ClassPublic
		if c.Column == "email" {
			c.Class, c.EntityType = guard.ClassIdentifier, guard.EntityEmail
		}
		return c, err
	})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(context.Background(), d.Admin, func(tx pgx.Tx) error {
		return guard.WriteClassification(context.Background(), tx, d.Names, guard.Classification{Columns: cols, At: time.Now()})
	}))
	dir := t.TempDir()
	keys, err := pii.LoadKeys(filepath.Join(dir, pii.KeyFileName), rand.Reader)
	require.NoError(t, err)
	dict, err := pii.OpenDictionary(dir, keys, pii.DefaultDictionaryOptions())
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	env := pgService(t, a.URL, withReturned(returned), withDeps(func(deps *agent.Deps, pool *pgxpool.Pool) {
		if obs == nil {
			obs = piidict.NewObserver(piidict.NewMap(slog.New(slog.DiscardHandler)), dict).On(pool)
		}
		deps.PII = obs
	}))
	return env.Svc, d, dict, keys
}

func TestQueryAddsIdentifierValuesBeforeItReturns(t *testing.T) {
	t.Parallel()
	svc, _, dict, keys := piiService(t, nil, nil)
	out, err := svc.Query(context.Background(), agent.QueryParams{SQL: `SELECT id, email, city FROM people ORDER BY id`})
	require.NoError(t, err)
	require.Len(t, out.Rows, 2)
	for _, v := range []string{"ann@corp.ee", "ben@corp.ee"} {
		require.True(t, dict.Contains(pii.EntityEmail, keys.TypedHash(pii.EntityEmail, v, "")), v)
	}
	_, ok := dict.Lookup(keys.GenericHash("Tartu"))
	require.False(t, ok, "a PUBLIC column is not added")
}

// failingObserver cannot add any value.
type failingObserver struct{}

func (failingObserver) Observe(context.Context, []action.Column, []map[string]any) error {
	return errors.New("pii: dictionary delta is full")
}

func TestQueryWithholdsRowsTheDictionaryCannotTake(t *testing.T) {
	t.Parallel()
	svc, d, _, _ := piiService(t, failingObserver{}, nil)
	out, err := svc.Query(context.Background(), agent.QueryParams{SQL: `SELECT email FROM people`})
	require.Error(t, err)
	require.Empty(t, out.Rows)
	require.Equal(t, agent.CodeInternal, agent.ToolError(err).Code)
	var reads int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(change_id) FROM basalt_meta.changes WHERE op = 'SELECT'`).Scan(&reads))
	require.Zero(t, reads, "a read the agent did not get is not recorded as one")
}

func TestWriteRollsBackWhenItsReturnedValuesCannotBeAdded(t *testing.T) {
	t.Parallel()
	refuse := func(context.Context, pgx.Tx, []action.Column, []map[string]any) error { return pii.ErrDeltaFull }
	svc, d, _, _ := piiService(t, failingObserver{}, refuse)
	_, err := svc.Write(context.Background(), agent.WriteParams{
		SQL: `UPDATE people SET city = 'Pärnu' WHERE id = 1 RETURNING email`, Intent: "move ann",
	})
	require.ErrorIs(t, err, pii.ErrDeltaFull)
	var city string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT city FROM people WHERE id = 1`).Scan(&city))
	require.Equal(t, "Tartu", city, "the write was rolled back")
}
