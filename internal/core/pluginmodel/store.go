package pluginmodel

import "errors"

// StoreReason is what an agent's store answered to a call of the plugin
// host's ledger port, in the plugin's own words. The store's adapter maps
// its own answers to one, per call; the plugin host decides on it. Reasons
// are internal: they never reach the wire.
type StoreReason string

const (
	// StoreGuardMissing: the store has no guard to record plugins in.
	StoreGuardMissing StoreReason = "GUARD_MISSING"
	// StoreGuardOutdated: the store's guard is older than the call needs.
	StoreGuardOutdated StoreReason = "GUARD_OUTDATED"
	// StoreRefused: the guard refused the call.
	StoreRefused StoreReason = "REFUSED"
	// StoreTooManyPending: opening a plugin approval found as many waiting
	// as the guard holds.
	StoreTooManyPending StoreReason = "TOO_MANY_PENDING"
	// StoreUnknownAgent: a plugin approval names an agent the store does not
	// know.
	StoreUnknownAgent StoreReason = "UNKNOWN_AGENT"
	// StoreAnswered: the store answered with an error no other reason
	// names.
	StoreAnswered StoreReason = "ANSWERED"
)

// StoreError is the store's answer to a ledger call that failed: the store
// answered, so the failure is not a lost connection. An error the store
// did not answer (no connection, a timeout) is never one.
type StoreError struct {
	Reason StoreReason
	// Code is the store's own error code, passed on as it is.
	Code string
	// Message is the store's own text, verbatim.
	Message string
	// Err is the store's own error, kept in the chain for its other
	// readers.
	Err error
}

// Error is the store's own text, or the reason and message without one.
func (e *StoreError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "store answered " + string(e.Reason) + ": " + e.Message
}

func (e *StoreError) Unwrap() error { return e.Err }

// StoreErrorOf is the store's answer in err's chain, nil when there is
// none.
func StoreErrorOf(err error) *StoreError {
	var se *StoreError
	if !errors.As(err, &se) {
		return nil
	}
	return se
}

// ApprovalReason is why the store refused the person's signed plugin
// approval, in the plugin's own words. The store's adapter maps its own
// answers to one; the plugin approval page decides on it.
type ApprovalReason string

const (
	// ApprovalExpired: the approval expired before it was signed.
	ApprovalExpired ApprovalReason = "EXPIRED"
	// ApprovalAlreadyApproved: the approval is already signed.
	ApprovalAlreadyApproved ApprovalReason = "ALREADY_APPROVED"
	// ApprovalCancelled: a newer approval for the same plugin replaced it.
	ApprovalCancelled ApprovalReason = "CANCELLED"
	// ApprovalWithdrawn: the agent that opened it withdrew it.
	ApprovalWithdrawn ApprovalReason = "WITHDRAWN"
	// ApprovalNotFound: the store holds no such approval for the agent.
	ApprovalNotFound ApprovalReason = "NOT_FOUND"
	// ApprovalPasskeyRevoked: the passkey that signed it is unknown or
	// revoked.
	ApprovalPasskeyRevoked ApprovalReason = "PASSKEY_REVOKED"
	// ApprovalBadSignature: the signature did not verify.
	ApprovalBadSignature ApprovalReason = "BAD_SIGNATURE"
)

// ApprovalRefusalError is a signed plugin approval the store refused, as
// the store's adapter maps it. It wraps the adapter's own error, so any
// other reader of that error (the answer's message) still finds it.
type ApprovalRefusalError struct {
	Reason ApprovalReason
	// Err is the store's own error.
	Err error
}

// Error is the store's own text, or the reason without one.
func (e *ApprovalRefusalError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "plugin approval refused: " + string(e.Reason)
}

func (e *ApprovalRefusalError) Unwrap() error { return e.Err }

// ApprovalRefusalOf is the plugin approval refusal in err's chain, nil when
// there is none.
func ApprovalRefusalOf(err error) *ApprovalRefusalError {
	var ar *ApprovalRefusalError
	if !errors.As(err, &ar) {
		return nil
	}
	return ar
}
