// Package revertstore holds the types the revert domain's store ports are
// written in: a revert's scope, preview, plan, lines, batches, rescope,
// reject and reveal, and the store's typed refusals (RevertRefusalError
// and its RevertReason), in words that fit any store. The ledger records
// other domains read too (action.Revert and RevertListParams) stay in
// internal/core/action. The store's adapter fills these types;
// internal/revert decides on them. Types only.
package revertstore
