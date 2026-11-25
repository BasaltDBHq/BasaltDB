package pgpii

import (
	"context"
	"crypto/rand"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// scanDict is a dictionary in its own state directory, with keys, for the
// scan tests.
func scanDict(t *testing.T, keys *corepii.Keys) (*corepii.FuseDictionary, *corepii.Keys, string) {
	t.Helper()
	dir := t.TempDir()
	if keys == nil {
		var err error
		keys, err = dictfile.LoadKeys(dir+"/"+corepii.KeyFileName, rand.Reader)
		require.NoError(t, err)
	}
	dict, err := dictfile.Open(dir, keys, corepii.DefaultDictionaryOptions(time.Now))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	return dict, keys, dir
}

// scanSource is the agent "bot" scanned through pool.
func scanSource(pool Pool, limits sqlguard.Limits) pii.ScanSource {
	return pii.ScanSource{
		Agent: "bot", Map: pii.NewMap(slog.New(slog.DiscardHandler)), Classes: Classes(pool),
		Fields: Fields(pool, limits, pii.DefaultLoadTimeout),
	}
}

func TestScanRebuildsFromEveryKindOfRelation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys, dir := scanDict(t, nil)
	log, out := newLog()
	var slept time.Duration
	clock := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s := pii.NewScanner(dict, []pii.ScanSource{scanSource(f.pool, sqlguard.DefaultLimits())},
		pii.ScanOptions{
			PageRows: 2, RowsPerSecond: 4, Now: func() time.Time { return clock },
			Sleep: func(_ context.Context, d time.Duration) error { slept += d; clock = clock.Add(d); return nil },
		}, log)

	res, err := s.Cycle(ctx)
	require.NoError(t, err)
	require.Equal(t, 6, res.Columns)
	require.False(t, dict.NeedsBuild())
	require.Zero(t, dict.Status().DeltaValues)
	for _, v := range []string{"ada@corp.ee", "bob@corp.ee", "nk1@corp.ee", "nk2@corp.ee", "order1@corp.ee", "order7@corp.ee"} {
		require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, v, "")), v)
	}
	_, ok := dict.Lookup(keys.GenericHash("Bob Stone"))
	require.True(t, ok)
	// customers 3 + nokey 3 + orders 7 rows, and the view's 3 distinct
	// values: paged two rows at a time and held to 4 rows a second.
	require.EqualValues(t, 16, res.Rows)
	require.Equal(t, time.Duration(res.Rows)*time.Second/4, slept)
	require.Contains(t, out.String(), "pii: dictionary scan")
	require.NotContains(t, out.String(), "corp.ee", "the log carries counts, never values")

	st, ok := dictfile.ReadStatus(dir)
	require.True(t, ok)
	require.EqualValues(t, 16, st.LastScanRows)

	// A deleted value drops out at the next cycle (M51-8).
	f.db.Exec(t, `DELETE FROM public.nokey WHERE email = 'nk2@corp.ee'`)
	_, err = s.Cycle(ctx)
	require.NoError(t, err)
	require.False(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "nk2@corp.ee", "")))
}

func TestScanOverBudgetKeepsThePreviousDictionary(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	ctx := context.Background()
	dict, keys, _ := scanDict(t, nil)
	src := []pii.ScanSource{scanSource(f.pool, sqlguard.DefaultLimits())}
	_, err := pii.NewScanner(dict, src, pii.ScanOptions{}, slog.New(slog.DiscardHandler)).Cycle(ctx)
	require.NoError(t, err)
	require.NoError(t, dict.Add(corepii.EntityEmail, "delta@corp.ee", ""))

	// A budget for 3 values: the cycle stops, the base and delta stay.
	tiny := pii.NewScanner(dict, src, pii.ScanOptions{MaxMemoryBytes: 3 * pii.BytesPerAddBound}, slog.New(slog.DiscardHandler))
	_, err = tiny.Cycle(ctx)
	require.ErrorIs(t, err, pii.ErrScanOverBudget)
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "order7@corp.ee", "")))
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "delta@corp.ee", "")))
	require.Equal(t, 1, dict.Status().DeltaValues)
}

func TestScanSkipsAKeylessRelationThatTimesOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// A view too slow to read within the statement timeout.
	f.db.Exec(t, `CREATE VIEW public.slow_v AS SELECT c.email AS mail FROM public.customers c
		CROSS JOIN LATERAL (SELECT pg_sleep(0.3)) s;
		GRANT SELECT ON public.slow_v TO `+f.agent.Role)
	f.classifyWith(t, time.Now(), map[string]string{"slow_v.mail": guardmodel.EntityEmail})
	ctx := context.Background()
	dict, keys, _ := scanDict(t, nil)
	limits := sqlguard.DefaultLimits()
	limits.StatementTimeout = 200 * time.Millisecond
	log, out := newLog()
	s := pii.NewScanner(dict, []pii.ScanSource{scanSource(f.pool, limits)}, pii.ScanOptions{}, log)

	res, err := s.Cycle(ctx)
	require.NoError(t, err, "the slow view is skipped, the cycle commits")
	require.Equal(t, 1, res.Skipped)
	require.True(t, dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, "order7@corp.ee", "")))
	require.Contains(t, out.String(), "pii: skipped a relation in this scan")
	require.Contains(t, out.String(), "public.slow_v")
	require.NotContains(t, out.String(), "corp.ee", "names and counts only")
}

func TestScanWarnsWhenBuildsKeepFailing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.classify(t, time.Now())
	pool, err := postgres.NewPool(context.Background(), f.agent.URL, 1)
	require.NoError(t, err)
	pool.Close() // every cycle fails
	dict, _, _ := scanDict(t, nil)
	log, out := newLog()
	s := pii.NewScanner(dict, []pii.ScanSource{scanSource(pool, sqlguard.DefaultLimits())}, pii.ScanOptions{}, log)
	for i := range pii.FailWarnAfter {
		_, err := s.Cycle(context.Background())
		require.Error(t, err)
		require.Equal(t, i == pii.FailWarnAfter-1, strings.Contains(out.String(), "has not been rebuilt"), "cycle %d", i)
	}
}

// A json, a jsonb and a text column give the scan the same dictionary text
// as the query tool: a JSON string unquoted, a text value as written.
func TestScanTextMatchesTheQueryTool(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.db.Exec(t, `CREATE TABLE public.docs (id bigint PRIMARY KEY, j json, jb jsonb, t text);
		INSERT INTO public.docs VALUES (1, '"j@corp.ee"', '"jb@corp.ee"', '"t@corp.ee"'),
		                               (2, '{"e": "jo@corp.ee"}', '{"e": "jbo@corp.ee"}', 'tt@corp.ee');
		GRANT SELECT ON public.docs TO `+f.agent.Role)
	f.classifyWith(t, time.Now(), map[string]string{
		"docs.j": guardmodel.EntityEmail, "docs.jb": guardmodel.EntityEmail, "docs.t": guardmodel.EntityEmail,
	})
	ctx := context.Background()
	scanned, keys, _ := scanDict(t, nil)
	_, err := pii.NewScanner(scanned, []pii.ScanSource{scanSource(f.pool, sqlguard.DefaultLimits())}, pii.ScanOptions{},
		slog.New(slog.DiscardHandler)).Cycle(ctx)
	require.NoError(t, err)

	read, _, _ := scanDict(t, keys)
	res, err := postgres.NewReader(f.pool, sqlguard.DefaultLimits(), time.Now).
		Read(ctx, `SELECT j, jb, t FROM public.docs`, nil, action.Statement{})
	require.NoError(t, err)
	fields := make([]piistore.ResultField, len(res.Columns))
	for i, c := range res.Columns {
		fields[i] = piistore.ResultField{Ref: c.Ref, Key: c.Name}
	}
	obs := pii.NewObserver(pii.NewMap(slog.New(slog.DiscardHandler)), read).On(Classes(f.pool))
	require.NoError(t, obs.Observe(ctx, fields, res.Rows))

	for v, want := range map[string]bool{
		"j@corp.ee": true, `"j@corp.ee"`: false,
		"jb@corp.ee": true, `"jb@corp.ee"`: false,
		`"t@corp.ee"`: true, "t@corp.ee": false, "tt@corp.ee": true,
		`{"e": "jbo@corp.ee"}`: true,
	} {
		h := keys.TypedHash(corepii.EntityEmail, v, "")
		require.Equal(t, want, read.Contains(corepii.EntityEmail, h), "query tool: %s", v)
		require.Equal(t, want, scanned.Contains(corepii.EntityEmail, h), "scan: %s", v)
	}
	// The json object keeps the text Postgres stores; whatever it is, both
	// paths agree on it.
	var jo string
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT j::text FROM public.docs WHERE id = 2`).Scan(&jo))
	h := keys.TypedHash(corepii.EntityEmail, jo, "")
	require.True(t, read.Contains(corepii.EntityEmail, h))
	require.True(t, scanned.Contains(corepii.EntityEmail, h))
}
