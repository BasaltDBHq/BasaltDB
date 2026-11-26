package servedagent_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// stampsEnv: an agent that moved every row's timestamptz of public.stamps
// by a day in one run. The guard writes a revert line's values as
// to_jsonb prints them ("+00:00"); what the agent is shown goes through the
// revert store set's ShowValues, which the wiring sets to wiretime.JSON.
func stampsEnv(t *testing.T, rows int) (agentEnv, uuid.UUID) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.stamps (id int PRIMARY KEY, at timestamptz NOT NULL);
		INSERT INTO public.stamps SELECT g, timestamptz '2026-11-10 06:02:11.5+00' + g * interval '1 minute'
		FROM generate_series(1, %d) g`, rows))
	tables := []string{"public.stamps"}
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables))
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Move the stamps"}
	require.NoError(t, guard.StartRun(ctx, e.a.Conn, in))
	stmts := make([]string, 0, rows/10+1)
	for i := 0; i < rows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.stamps SET at = at + interval '1 day' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, e.a.Conn, in, stmts...))
	return e, in.RunID
}

// utcStamp is a stamp of stampsEnv as the wire shows it: RFC 3339 UTC, Z.
var utcStamp = regexp.MustCompile(`^2026-11-1[01]T\d\d:\d\d:11\.5Z$`)

func requireUTCStamp(t *testing.T, image any, what string) {
	t.Helper()
	m, ok := image.(map[string]any)
	require.True(t, ok, "%s: %v", what, image)
	at, ok := m["at"].(string)
	require.True(t, ok, "%s names at: %v", what, m)
	require.Regexp(t, utcStamp, at, "%s: a timestamptz is shown RFC 3339 UTC with Z", what)
}

// A preview's line shows a timestamptz as the wire format has it: the
// revert store set's ShowValues (wiretime.JSON) reaches the preview.
func TestPreviewRevertShowsTimestamptzAsUTC(t *testing.T) {
	t.Parallel()
	e, run := stampsEnv(t, 1)
	page := callFits(t, e.h, "preview_revert", map[string]any{"runId": run.String()})
	lines := items(t, page)
	require.Len(t, lines, 1)
	require.Equal(t, "2026-11-11T06:03:11.5Z", lines[0]["now"].(map[string]any)["at"], "now: the agent's value")
	require.Equal(t, "2026-11-10T06:03:11.5Z", lines[0]["set"].(map[string]any)["at"], "set: the value the revert restores")
}

// A batched plan's lines, read back from the ledger (revert_plan), show a
// timestamptz the same way.
func TestRevertPlanShowsTimestamptzAsUTC(t *testing.T) {
	t.Parallel()
	e, run := stampsEnv(t, planRows)
	prep, err := guard.PrepareRevert(context.Background(), e.a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: run}, "Undo the move")
	require.NoError(t, err)
	require.True(t, prep.Batched)
	page := callFits(t, e.h, "revert_plan", map[string]any{"revertId": prep.RevertID.String(), "limit": 20})
	lines := items(t, page)
	require.Len(t, lines, 20)
	for _, l := range lines {
		plan, ok := l["plan"].(map[string]any)
		require.True(t, ok, "%v", l)
		requireUTCStamp(t, plan["now"], "plan now")
		requireUTCStamp(t, plan["set"], "plan set")
	}
}
