package stepcatalogtest

import "slices"

// The catalog's revert cases run in the revert package's tests, on the
// revert use case's own builders. These are their keys: the revert tests
// require their cases to be exactly these, and the agent's tests, which run
// the rest of the catalog, require every catalog entry to have a case among
// their own or these.

// RevertErrorKeys are the CaseKeys of the error cases the revert package runs.
func RevertErrorKeys() []string {
	return sorted(
		CaseKey("NOT_FOUND", "REVERT", ""),
		CaseKey("NOT_FOUND", "TASK", ""),
		CaseKey("NOTHING_TO_REVERT", "ALL_CHANGED_BY_PEOPLE", ""),
		CaseKey("NOTHING_TO_REVERT", "ALREADY_REVERTED", ""),
		CaseKey("NOTHING_TO_REVERT", "READS_ONLY", ""),
		CaseKey("QUERY_TIMEOUT", "TIME_LIMIT", "preview_revert"),
		CaseKey("QUERY_TIMEOUT", "TIME_LIMIT", "request_revert"),
		CaseKey("REVERT_EXPIRED", "NOT_FINISHED", ""),
		CaseKey("REVERT_EXPIRED", "NOT_SIGNED", ""),
		CaseKey("REVERT_INVALID", "BAD_SIGNATURE", ""),
		CaseKey("REVERT_INVALID", "LINE_INVALID", ""),
		CaseKey("REVERT_INVALID", "NOT_THIS_AGENT", ""),
		CaseKey("REVERT_INVALID", "PASSKEY_REVOKED", ""),
		CaseKey("REVERT_INVALID", "PLAN_FINISHED", ""),
		CaseKey("REVERT_INVALID", "PLAN_NOT_SIGNED", ""),
		CaseKey("REVERT_INVALID", "ROWS_CHANGED", ""),
	)
}

// RevertResultKeys are the keys (tool|case) of the result cases the revert
// package runs.
func RevertResultKeys() []string {
	return sorted(
		"apply_revert_batch|APPLIED",
		"apply_revert_batch|APPLYING",
		"list_pending|REVERT_APPLYING",
		"list_pending|REVERT_PENDING",
		"preview_revert|PREVIEW",
		"preview_revert|PREVIEW_TASK",
		"request_revert|APPLIED",
		"request_revert|APPLYING",
		"request_revert|EXPIRED",
		"request_revert|REJECTED",
		"request_revert|REQUESTED",
		"request_revert|REQUESTED_NO_PAGES",
		"request_revert|REQUEST_TOO_LARGE",
		"request_revert|WAIT_ENDED",
		"revert_plan|APPLIED",
		"revert_plan|APPLYING",
		"revert_plan|EXPIRED",
		"revert_plan|PENDING",
		"revert_plan|REJECTED",
		"revert_plan|REQUEST_TOO_LARGE",
	)
}

func sorted(keys ...string) []string {
	slices.Sort(keys)
	return keys
}
