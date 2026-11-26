package servedagent_test

import (
	"encoding/base64"
	"testing"
)

// Every paged tool answers the same bad cursors the same way: INVALID_ARGUMENT
// STALE_CURSOR, refused before any SQL. A cursor whose id is not a UUID used
// to reach Postgres from the ledger's lists and come back as STORE_ERROR.
func TestEveryPagedToolAnswersAStaleCursor(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	runID, revertID := e.runID.String(), e.prep.RevertID.String()
	tools := []struct {
		tool string
		args map[string]any
	}{
		{"list_runs", map[string]any{}},
		{"run_history", map[string]any{"runId": runID}},
		{"list_pending", map[string]any{}},
		{"preview_revert", map[string]any{"runId": runID}},
		{"revert_plan", map[string]any{"revertId": revertID}},
		{"describe", map[string]any{"query": "items"}},
	}
	cursors := []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"id":"x"}`)),
	}
	for _, tc := range tools {
		for _, c := range cursors {
			args := map[string]any{"cursor": c}
			for k, v := range tc.args {
				args[k] = v
			}
			body, isError := e.h.call(t, tc.tool, args)
			requireToolError(t, body, isError, "INVALID_ARGUMENT", "STALE_CURSOR", "")
		}
	}
}
