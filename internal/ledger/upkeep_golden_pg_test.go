package ledger_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata/")

var (
	goldenTime = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)`)
	goldenHash = regexp.MustCompile(`\b[0-9a-f]{64}\b`)
)

// normal replaces what differs from run to run (times, hashes, the database
// and the role prefix) in a decoded JSON value.
func normal(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normal(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normal(val)
		}
		return out
	case string:
		return goldenHash.ReplaceAllString(goldenTime.ReplaceAllString(x, "<time>"), "<hash>")
	}
	return v
}

func requireGolden(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&decoded))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(normal(decoded)))
	file := filepath.Join("testdata", name+".json")
	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, buf.Bytes(), 0o600))
	}
	want, err := os.ReadFile(file)
	require.NoError(t, err, "run with -update to write %s", file)
	require.Equal(t, string(want), buf.String(), "%s (run with -update to rewrite)", file)
}

// state is what one Tick leaves behind: the events it recorded, in order,
// and the chain's status as the person's log reads it.
func state(t *testing.T, d *guardtest.DB) map[string]any {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(),
		`SELECT kind, detail FROM basalt_meta.ledger WHERE kind <> 'ROW_CHANGE' ORDER BY seq`)
	require.NoError(t, err)
	defer rows.Close()
	var events []any
	for rows.Next() {
		var kind string
		var detail map[string]any
		require.NoError(t, rows.Scan(&kind, &detail))
		events = append(events, map[string]any{"kind": kind, "detail": detail})
	}
	require.NoError(t, rows.Err())
	health, err := checkHealth(context.Background(), d.Admin, time.Now(), healthOptions{})
	require.NoError(t, err)
	return map[string]any{"events": events, "chain": health.Chain, "heartbeatStale": health.HeartbeatStale}
}

// A tick on a fresh database, then another after a table the agent's
// cascades reach has no guard: the events recorded and the chain status are
// pinned, so moving the upkeep behind another interface must change neither.
func TestTickGolden(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, nil)
	ctx := context.Background()
	u := newUpkeep(a.Conn, time.Now)

	require.NoError(t, u.Tick(ctx))
	requireGolden(t, "tick_fresh", state(t, d))

	d.Exec(t, `CREATE TABLE public.lead_files (id bigint PRIMARY KEY, lead_id bigint REFERENCES public.leads ON DELETE CASCADE)`)
	require.NoError(t, u.Tick(ctx))
	requireGolden(t, "tick_uncovered_table", state(t, d))
}
