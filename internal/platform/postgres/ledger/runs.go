package ledger

// RunSortSpec whitelists the run list sort, the same as the change list's:
// id or -id, newest first by default (run ids are UUIDv7, so id order is
// start order).
var RunSortSpec = ChangeSortSpec
