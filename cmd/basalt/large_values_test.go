package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// A value over 1 MiB is printed in full, followed by its size and sha256 so
// the person can match it to the marker the agent saw. --json is not touched.
func TestLogTextMarksLargeValues(t *testing.T) {
	t.Parallel()
	mark := "(2.0 MiB, sha256 " + strings.Repeat("ab", 32) + ")"
	r := ledger.RowChange{
		Table: "public.docs", Op: "UPDATE",
		Key:    map[string]any{"id": 1.0},
		Before: map[string]any{"body": "old", "n": 1.0},
		After:  map[string]any{"body": "BIG", "n": 2.0},
		Marks:  largevalue.Marks{After: map[string]string{"body": mark}},
	}
	require.Equal(t, `UPDATE public.docs {"id":1} body old -> BIG `+mark+`, n 1 -> 2`, rowLine(r, false))
	require.Equal(t, `UPDATE public.docs {"id":1} before={"body":"old","n":1} after={"body":"BIG" `+mark+`,"n":2}`, rowLine(r, true))

	r.Marks = largevalue.Marks{}
	require.NotContains(t, rowLine(r, true), "sha256")
	rec := ledger.RecordFromDomain(ledger.Change{}, []ledger.RowChange{{Marks: largevalue.Marks{After: map[string]string{"body": mark}}}})
	b, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NotContains(t, string(b), "sha256")
}

func TestRevertTextMarksLargeValues(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("<", largevalue.ValueCap/7+1)
	sum := largevalue.Summary([]byte(`"`+big+`"`), "body")
	require.NotEmpty(t, sum)
	l := revert.Line{
		Op: "UPDATE", Table: "public.docs", Action: revert.ActionRestore,
		Key: json.RawMessage(`{"id": 1}`),
		Now: json.RawMessage(`{"body": "` + big + `", "id": 1}`),
		Set: json.RawMessage(`{"body": "small", "id": 1}`),
	}
	got := revertLine(l)
	require.True(t, got == `restore    public.docs {"id": 1}: body: "`+big+`" `+sum+` -> "small"`, "now's large value is followed by its summary")

	l.Now, l.Set = l.Set, l.Now
	require.True(t, revertLine(l) == `restore    public.docs {"id": 1}: body: "small" -> "`+big+`" `+sum, "set's large value is followed by its summary")

	// A large key value is followed by its column and summary.
	l.Key = json.RawMessage(`{"id": "` + big + `"}`)
	l.Now, l.Set = nil, nil
	require.True(t, strings.HasSuffix(revertLine(l), `"} id `+sum), "the key's summary follows the key")
}
