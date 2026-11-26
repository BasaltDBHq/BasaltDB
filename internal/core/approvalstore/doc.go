// Package approvalstore holds the types the approval domain's store ports
// are written in: listing held writes, a held write's preview, hold and
// reveal, and the store's typed refusals (ApprovalRefusalError and its
// ApprovalReason), in words that fit any store. The ledger record other
// domains read too (action.Approval) stays in internal/core/action. The
// store's adapter fills these types; internal/approval decides on them.
// Types only.
package approvalstore
