package sqlguard

import (
	"errors"
	"strconv"
	"time"
)

// Default limits for agent statements (the default
// policy: a SELECT runs within a row limit and a time limit).
//
// DefaultStatementTimeout is the engine's limit on one agent statement,
// set on each transaction. It is deliberately shorter than the role
// default a setup writes (guardmodel.DefaultRoleStatementTimeout, 30s),
// which only bounds a connection that does not go through the engine.
const (
	DefaultStatementTimeout = 5 * time.Second
	DefaultReadRowLimit     = 1000

	// maxStatementTimeout and maxReadRowLimit bound what an operator can
	// configure; agents never set limits.
	maxStatementTimeout = 10 * time.Minute
	maxReadRowLimit     = 100_000
)

// Limits bound one agent statement.
type Limits struct {
	// StatementTimeout is set transaction-locally on every agent transaction.
	StatementTimeout time.Duration
	// ReadRowLimit is the most rows a query may return; a query over it is
	// canceled and refused.
	ReadRowLimit int
}

// DefaultLimits returns the M1 defaults.
func DefaultLimits() Limits {
	return Limits{StatementTimeout: DefaultStatementTimeout, ReadRowLimit: DefaultReadRowLimit}
}

// Validate checks the limits are positive and within the operator bounds.
func (l Limits) Validate() error {
	if l.StatementTimeout < time.Millisecond || l.StatementTimeout > maxStatementTimeout {
		return errors.New("statement timeout must be between 1ms and 10m")
	}
	if l.ReadRowLimit < 1 || l.ReadRowLimit > maxReadRowLimit {
		return errors.New("read row limit must be between 1 and 100000")
	}
	return nil
}

// StatementTimeoutSetting is the value for
// set_config('statement_timeout', ..., true), in milliseconds.
func (l Limits) StatementTimeoutSetting() string {
	return strconv.FormatInt(l.StatementTimeout.Milliseconds(), 10)
}
