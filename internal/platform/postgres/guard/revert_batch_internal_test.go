package guard

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// TestDecodeBatchResultMapsSQLStateToStoreCode: apply_revert_batch answers
// a line's SQLSTATE as sqlState (006_reverts.sql); the decode keeps it as
// the line's StoreCode, so renaming the store-neutral field never drops it.
func TestDecodeBatchResultMapsSQLStateToStoreCode(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("0b8f6c3e-6a1f-4d3a-9b8e-2f4c1d7a9e10")
	raw := []byte(`{"revertId": "` + id.String() + `", "batch": 2, "status": "APPLYING", "restored": 5, "skipped": 2, "pending": 7,
		"items": [
			{"line": 3, "outcome": "SKIPPED", "conflict": "KEY_TAKEN", "sqlState": "23505"},
			{"line": 4, "outcome": "SKIPPED", "conflict": "CHANGED_AFTER", "sqlState": null},
			{"line": 5, "outcome": "RESTORED", "conflict": null}
		]}`)
	got, err := decodeBatchResult(raw)
	require.NoError(t, err)
	require.Equal(t, action.BatchResult{
		RevertID: id, Batch: 2, Status: "APPLYING", Restored: 5, Skipped: 2, Pending: 7,
		Items: []action.BatchItem{
			{Line: 3, Outcome: "SKIPPED", Conflict: "KEY_TAKEN", StoreCode: "23505"},
			{Line: 4, Outcome: "SKIPPED", Conflict: "CHANGED_AFTER"},
			{Line: 5, Outcome: "RESTORED"},
		},
	}, got)
}

// TestDecodeBatchResultRefusesBadJSON: an answer that does not decode is an
// error, never an empty batch.
func TestDecodeBatchResultRefusesBadJSON(t *testing.T) {
	t.Parallel()
	_, err := decodeBatchResult([]byte(`{"items": "no"}`))
	require.Error(t, err)
}
