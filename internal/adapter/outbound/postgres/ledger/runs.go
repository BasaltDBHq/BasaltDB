package ledger

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// RunSortSpec whitelists the run list sort, the same as the change list's:
// id or -id, newest first by default (run ids are UUIDv7, so id order is
// start order).
var RunSortSpec = ChangeSortSpec

// RunListParams lists the calling agent's own runs (list_runs). StartTime
// (inclusive) and EndTime (exclusive) filter on the run's start; nil means
// no bound. The handler applies pagination defaults and the clamp before
// calling.
type RunListParams struct {
	pagination.Params
	StartTime *time.Time `json:"startTime"`
	// EndTime must be after StartTime when both are given: excluded_with
	// passes when there is no StartTime, gtfield checks the order otherwise.
	EndTime *time.Time `json:"endTime" validate:"excluded_with=StartTime|gtfield=StartTime"`
}
