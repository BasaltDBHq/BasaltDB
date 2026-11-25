package action

import "errors"

var (
	// ErrRowLimit is a read canceled because it returned more rows than the
	// engine's read row limit.
	ErrRowLimit = errors.New("the query returned more rows than the read row limit")
	// ErrRunNotFound is a run id that is not one of this agent's runs.
	ErrRunNotFound = errors.New("run not found")
	// ErrApprovalRequired is a write the store held for the person's
	// approval (a *StoreError with CodeApprovalRequired is this error).
	ErrApprovalRequired = errors.New("the write needs the person's approval")
	// ErrUnavailable is a store the engine could not reach.
	ErrUnavailable = errors.New("the store cannot be reached")
	// ErrMessageTooLarge is a message from the store over the engine's cap:
	// one row too large to read.
	ErrMessageTooLarge = errors.New("a message from the store is over the engine's cap")
	// ErrNotFound is a lookup the store found nothing for.
	ErrNotFound = errors.New("not found in the store")
)

// StoreError is a failure the store answered with, mapped by the store's
// adapter to the contract: Code and Reason are the tool error's, Message
// its text. StoreCode (in Postgres the SQLSTATE), Detail and Hint are the
// store's own, LedgerCode the ledger's code for its own refusals ("" for any other failure). Error is
// the store's original text, and Unwrap the original error, which is
// required.
type StoreError struct {
	Code       string
	Reason     string
	Message    string
	StoreCode  string
	Detail     string
	Hint       string
	LedgerCode string
	Err        error
}

func (e *StoreError) Error() string { return e.Err.Error() }

func (e *StoreError) Unwrap() error { return e.Err }

// Is makes a held write ErrApprovalRequired.
func (e *StoreError) Is(target error) bool {
	return target == ErrApprovalRequired && e.Code == CodeApprovalRequired
}

// marked carries a store's own error as one of the errors above, keeping
// its text.
type marked struct {
	err, as error
}

func (m marked) Error() string   { return m.err.Error() }
func (m marked) Unwrap() []error { return []error{m.err, m.as} }

// Unavailable is err marked ErrUnavailable.
func Unavailable(err error) error { return marked{err: err, as: ErrUnavailable} }

// TooLarge is err marked ErrMessageTooLarge.
func TooLarge(err error) error { return marked{err: err, as: ErrMessageTooLarge} }

// NotFound is err marked ErrNotFound.
func NotFound(err error) error { return marked{err: err, as: ErrNotFound} }
