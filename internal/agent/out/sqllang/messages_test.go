package sqllang_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// TestLimitTextByReason pins the revision each limit asks for, as the
// agent reads it in its next steps.
func TestLimitTextByReason(t *testing.T) {
	t.Parallel()
	l := sqllang.Language{}
	for reason, want := range map[string]string{
		guidance.ReasonRowLimit: "Add a LIMIT or a narrower WHERE so the call returns fewer rows, then call it again.",
		guidance.ReasonRowTooLarge: "One row is too large to read whole: select fewer columns, the size of a large one " +
			"(length(col)) or a slice of it (substr(col, 1, 100000)), then call it again.",
		guidance.ReasonSizeLimit: "Select fewer or shorter columns (for example left(col, 200)) or fewer rows so the result stays under 16 MiB, then call it again.",
		"":                       "Narrow the statement (a tighter WHERE, fewer joins, a LIMIT) so it finishes in time, then call it again.",
	} {
		require.Equal(t, want, l.LimitText(reason), reason)
	}
}

func TestStaleTargetReadsTheGuardsDetail(t *testing.T) {
	t.Parallel()
	target, key, err := sqllang.Language{}.StaleTarget(`STALE_READ: public.leads {"id": 42} read at xmin 7, now 9`)
	require.NoError(t, err)
	require.Equal(t, "public.leads", target)
	require.Equal(t, map[string]any{"id": json.Number("42")}, key)
}

func TestStaleTargetRefusesADetailItCannotRead(t *testing.T) {
	t.Parallel()
	for _, msg := range []string{
		"STALE_READ: something else",
		`STALE_READ: public.leads {} read at xmin 7, now 9`,
		`STALE_READ: public.leads {"id": } read at xmin 7, now 9`,
	} {
		_, _, err := sqllang.Language{}.StaleTarget(msg)
		require.Error(t, err, msg)
	}
}

func TestDeniedTargetNamesTheTablePostgresNamed(t *testing.T) {
	t.Parallel()
	l := sqllang.Language{}
	for _, msg := range []string{"permission denied for table leads", "ERROR: permission denied for relation leads (SQLSTATE 42501)"} {
		table, ok := l.DeniedTarget(msg)
		require.True(t, ok, msg)
		require.Equal(t, "leads", table)
	}
	_, ok := l.DeniedTarget("permission denied for schema private")
	require.False(t, ok)
}

func TestNoKeyTargetNamesTheTableTheGuardNamed(t *testing.T) {
	t.Parallel()
	l := sqllang.Language{}
	table, ok := l.NoKeyTarget(`table public.logs has no primary key`)
	require.True(t, ok)
	require.Equal(t, "public.logs", table)
	_, ok = l.NoKeyTarget("some other refusal")
	require.False(t, ok)
}
