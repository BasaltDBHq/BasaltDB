package action

import "errors"

var (
	// ErrRowLimit is a read canceled because it returned more rows than the
	// engine's read row limit.
	ErrRowLimit = errors.New("the query returned more rows than the read row limit")
	// ErrRunNotFound is a run id that is not one of this agent's runs.
	ErrRunNotFound = errors.New("run not found")
)
