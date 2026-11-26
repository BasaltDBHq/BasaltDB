// Package approvalstore holds the types the approval domain's store ports
// are written in: a held write's preview, hold and reveal, and the store's
// typed refusals (ApprovalRefusalError and its ApprovalReason), in words that
// fit any store. The ledger records every domain shares (action.Approval and
// its list params) stay in internal/core/action. The store's adapter fills
// these types; internal/approval decides on them. Types only.
package approvalstore
