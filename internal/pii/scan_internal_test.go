package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// fakeFields is a store's reader in memory: each resource's rows, one value
// per field of the target (nil for none), or an error.
type fakeFields struct {
	rows    map[agentstore.ResourceRef][][]any
	errs    map[agentstore.ResourceRef]error
	targets []piistore.ScanTarget
	pages   []int
}

func (f *fakeFields) Read(_ context.Context, t piistore.ScanTarget, pageRows int, value func(int, any) error, page func(int) error) error {
	f.targets = append(f.targets, t)
	if err := f.errs[t.Resource]; err != nil {
		return err
	}
	rows := f.rows[t.Resource]
	for {
		n := min(pageRows, len(rows))
		for _, row := range rows[:n] {
			for i, v := range row {
				if v == nil {
					continue
				}
				if err := value(i, v); err != nil {
					return err
				}
			}
		}
		f.pages = append(f.pages, n)
		if err := page(n); err != nil {
			return err
		}
		rows = rows[n:]
		if n < pageRows {
			return nil
		}
	}
}

// identifier is an IDENTIFIER email field of resource.
func identifier(resource, name, field string) piistore.FieldClass {
	return piistore.FieldClass{
		Ref: agentstore.FieldRef(resource + "#" + field), Resource: agentstore.ResourceRef(resource),
		Namespace: "db", ResourceName: name, Field: field,
		Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityEmail,
	}
}

// scanFixture is two resources, listed out of order: "users" (two
// fields, three rows) and "accounts" (one field, one row).
func scanFixture() (*fakeClasses, *fakeFields) {
	classes := newFakeClasses(
		identifier("r2", "users", "work"), identifier("r2", "users", "home"),
		identifier("r1", "accounts", "owner"),
		piistore.FieldClass{Ref: "r2#note", Resource: "r2", Namespace: "db", ResourceName: "users", Field: "note", Class: guardmodel.ClassPublic},
	)
	fields := &fakeFields{rows: map[agentstore.ResourceRef][][]any{
		// home, work
		"r2": {{"a@corp.ee", json.RawMessage(`"b@corp.ee"`)}, {nil, ""}, {"c@corp.ee", nil}},
		"r1": {{"d@corp.ee"}},
	}, errs: map[agentstore.ResourceRef]error{}}
	return classes, fields
}

func newScan(t *testing.T, classes Classes, fields Fields, opts ScanOptions) (*Scanner, *corepii.FuseDictionary, *corepii.Keys, *logBuffer) {
	t.Helper()
	dict, keys := newDict(t, corepii.DefaultDictionaryOptions(time.Now))
	log, out := newLog()
	src := ScanSource{Agent: "bot", Map: NewMap(slog.New(slog.DiscardHandler)), Classes: classes, Fields: fields}
	return NewScanner(dict, []ScanSource{src}, opts, log), dict, keys, out
}

func hasEmail(dict *corepii.FuseDictionary, keys *corepii.Keys, v string) bool {
	return dict.Contains(corepii.EntityEmail, keys.TypedHash(corepii.EntityEmail, v, ""))
}

// The scan reads each resource's IDENTIFIER fields, resources by printed
// name and fields by name, adds every value as the read path does, and
// commits.
func TestScanReadsThroughFields(t *testing.T) {
	t.Parallel()
	classes, fields := scanFixture()
	s, dict, keys, out := newScan(t, classes, fields, ScanOptions{PageRows: 2})
	res, err := s.Cycle(context.Background())
	require.NoError(t, err)
	require.Equal(t, ScanResult{Columns: 3, Rows: 4, Values: 4}, res)
	require.Len(t, fields.targets, 2)
	require.Equal(t, piistore.ScanTarget{
		Resource: "r1", Namespace: "db", Name: "accounts",
		Fields: []piistore.FieldClass{identifier("r1", "accounts", "owner")},
	}, fields.targets[0])
	require.Equal(t, piistore.ScanTarget{
		Resource: "r2", Namespace: "db", Name: "users",
		Fields: []piistore.FieldClass{identifier("r2", "users", "home"), identifier("r2", "users", "work")},
	}, fields.targets[1])
	require.Equal(t, []int{1, 2, 1}, fields.pages)
	for _, v := range []string{"a@corp.ee", "b@corp.ee", "c@corp.ee", "d@corp.ee"} {
		require.True(t, hasEmail(dict, keys, v), v)
	}
	require.False(t, hasEmail(dict, keys, `"b@corp.ee"`), "a JSON string is unquoted")
	require.False(t, dict.NeedsBuild())
	require.Contains(t, out.String(), "pii: dictionary scan")
}

// The value invariant: the scan turns a value into dictionary text with the
// read path's valueText. A JSON string is unquoted, any other JSON keeps its
// text, and a string is taken as written, quotes and all.
func TestValueTextOfBothForms(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
		ok   bool
	}{
		{"a@corp.ee", "a@corp.ee", true},
		{`"a@corp.ee"`, `"a@corp.ee"`, true},
		{json.RawMessage(`"a@corp.ee"`), "a@corp.ee", true},
		{json.RawMessage(`{"e": "a@corp.ee"}`), `{"e": "a@corp.ee"}`, true},
		{json.RawMessage(`""`), "", false},
		{"", "", false},
		{nil, "", false},
	} {
		got, ok := valueText(c.v)
		require.Equal(t, c.want, got, "%#v", c.v)
		require.Equal(t, c.ok, ok, "%#v", c.v)
	}
}

// A resource the store says is unreadable or too slow is skipped with a
// warning and the cycle commits; its values are not added.
func TestScanSkipsWhatTheStoreSkips(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err error
		why string
	}{
		{fmt.Errorf("%w: gone", piistore.ErrUnreadable), "the agent can no longer read it"},
		{fmt.Errorf("%w: timeout", piistore.ErrTooSlow), "it has no key to page by and a full read exceeds the statement timeout"},
	} {
		classes, fields := scanFixture()
		fields.errs["r2"] = c.err
		s, dict, keys, out := newScan(t, classes, fields, ScanOptions{})
		res, err := s.Cycle(context.Background())
		require.NoError(t, err)
		require.Equal(t, ScanResult{Columns: 1, Rows: 1, Values: 1, Skipped: 1}, res)
		require.True(t, hasEmail(dict, keys, "d@corp.ee"))
		require.False(t, hasEmail(dict, keys, "a@corp.ee"))
		require.Contains(t, out.String(), "pii: skipped a relation in this scan: "+c.why)
		require.Contains(t, out.String(), "table=db.users")
		require.Contains(t, out.String(), "columns=2")
	}
}

// Any other store error fails the cycle and keeps the previous dictionary
// (fail closed); after three failures in a row the scan warns.
func TestScanFailsClosedAndWarns(t *testing.T) {
	t.Parallel()
	classes, fields := scanFixture()
	s, dict, keys, out := newScan(t, classes, fields, ScanOptions{})
	_, err := s.Cycle(context.Background())
	require.NoError(t, err)

	boom := errors.New("conn closed")
	fields.errs["r2"] = boom
	fields.rows["r1"] = [][]any{{"e@corp.ee"}}
	for i := range failWarnAfter {
		_, err := s.Cycle(context.Background())
		require.ErrorIs(t, err, boom)
		require.EqualError(t, err, "agent bot: scan db.users: conn closed")
		require.Equal(t, i == failWarnAfter-1, strings.Contains(out.String(), "has not been rebuilt"), "cycle %d", i)
	}
	require.True(t, hasEmail(dict, keys, "a@corp.ee"), "the previous base stays")
	require.False(t, hasEmail(dict, keys, "e@corp.ee"), "the aborted build is not committed")
}

// A build past the memory budget fails the cycle with ErrScanOverBudget;
// the previous base and the delta stay.
func TestScanOverBudget(t *testing.T) {
	t.Parallel()
	classes, fields := scanFixture()
	s, dict, keys, _ := newScan(t, classes, fields, ScanOptions{})
	_, err := s.Cycle(context.Background())
	require.NoError(t, err)
	require.NoError(t, dict.Add(corepii.EntityEmail, "delta@corp.ee", ""))

	tiny := NewScanner(dict, s.sources, ScanOptions{MaxMemoryBytes: 2 * bytesPerAddBound}, slog.New(slog.DiscardHandler))
	_, err = tiny.Cycle(context.Background())
	require.ErrorIs(t, err, ErrScanOverBudget)
	require.True(t, hasEmail(dict, keys, "a@corp.ee"))
	require.True(t, hasEmail(dict, keys, "delta@corp.ee"))
	require.Equal(t, 1, dict.Status().DeltaValues)
}

// The rate limit sleeps after each page, from the rows read so far.
func TestScanHoldsTheRate(t *testing.T) {
	t.Parallel()
	classes, fields := scanFixture()
	clock := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	var sleeps []time.Duration
	s, dict, _, _ := newScan(t, classes, fields, ScanOptions{
		PageRows: 2, RowsPerSecond: 2, Now: func() time.Time { return clock },
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			clock = clock.Add(d)
			return nil
		},
	})
	res, err := s.Cycle(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 4, res.Rows)
	require.False(t, dict.NeedsBuild())
	// Pages of 1, 2 and 1 rows at 2 rows a second.
	require.Equal(t, []time.Duration{500 * time.Millisecond, time.Second, 500 * time.Millisecond}, sleeps)
}
