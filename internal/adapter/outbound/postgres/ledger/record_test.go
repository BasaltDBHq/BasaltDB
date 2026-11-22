package ledger_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
)

// Row values in a change record are RFC 3339 UTC: the jsonb the guard stored
// carries the session zone of the write (CONTRACT.md, Wire format).
func TestRecordFromDomainTimestampsAreUTC(t *testing.T) {
	t.Parallel()
	rec := ledger.RecordFromDomain(ledger.Change{ID: uuid.Must(uuid.NewV7())}, []ledger.RowChange{{
		Table: "public.leads", Op: "UPDATE",
		Key:    map[string]any{"id": 1.0, "seen": "2026-11-12T14:08:04+02:00"},
		Before: map[string]any{"updated_at": "2026-11-12T14:08:04.513958+02:00", "note": "plain", "local": "2026-11-12T14:08:04"},
		After:  map[string]any{"updated_at": "2026-11-12T14:11:27+02:00", "tags": []any{"2026-11-12T00:00:00-05:00"}},
	}})
	row := rec.RowChanges[0]
	require.Equal(t, map[string]any{"id": 1.0, "seen": "2026-11-12T12:08:04Z"}, row.Key)
	require.Equal(t, map[string]any{"updated_at": "2026-11-12T12:08:04.513958Z", "note": "plain", "local": "2026-11-12T14:08:04"}, row.Before)
	require.Equal(t, map[string]any{"updated_at": "2026-11-12T12:11:27Z", "tags": []any{"2026-11-12T05:00:00Z"}}, row.After)
}
