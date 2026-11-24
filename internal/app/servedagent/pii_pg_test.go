package servedagent_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/app"

	"github.com/basaltdbhq/basaltdb/internal/testkit/agenttest"

	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// piiService is the engine's agent service with the PII observer wired as
// the engine wires it for query rows. (The write's RETURNING rows are
// internal/agent's TestWriteRollsBackWhenItsReturnedValuesCannotBeAdded.)
func piiService(t *testing.T, obs agentsvc.PIIObserver) (*app.Service, *guardtest.DB, *corepii.FuseDictionary, *corepii.Keys) {
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
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(filepath.Join(dir, corepii.KeyFileName), rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, corepii.DefaultDictionaryOptions(time.Now))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	env := agenttest.PgService(t, a.URL, agenttest.WithDeps(func(deps *app.Deps, pool *pgxpool.Pool) {
		if obs == nil {
			obs = pii.NewObserver(pii.NewMap(slog.New(slog.DiscardHandler)), dict).On(pgquerier.Neutralize(pool))
		}
		deps.Agent.PII = obs
	}))
	return env.Svc, d, dict, keys
}

// servedHarness serves svc's tools as the engine does.
func servedHarness(svc *app.Service) harness {
	return harness{server: mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, app.AgentTools(svc)...)}
}

func TestQueryAddsIdentifierValuesBeforeItReturns(t *testing.T) {
	t.Parallel()
	svc, _, dict, keys := piiService(t, nil)
	body, isError := servedHarness(svc).query(t, map[string]any{"sql": `SELECT id, email, city FROM people ORDER BY id`})
	require.False(t, isError, "%v", body)
	require.Len(t, body["rows"], 2)
	for _, v := range []string{"ann@corp.ee", "ben@corp.ee"} {
		require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, v, "")), v)
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
	svc, d, _, _ := piiService(t, failingObserver{})
	body, isError := servedHarness(svc).query(t, map[string]any{"sql": `SELECT email FROM people`})
	requireToolError(t, body, isError, guidance.CodeInternal, "", "")
	require.NotContains(t, body, "rows")
	var reads int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(change_id) FROM basalt_meta.changes WHERE op = 'SELECT'`).Scan(&reads))
	require.Zero(t, reads, "a read the agent did not get is not recorded as one")
}
