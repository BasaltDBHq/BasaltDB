package handoff

import "errors"

// ErrLoginRefused is a login the database refused: the agent's role does
// not exist or has another password.
var ErrLoginRefused = errors.New("the database refused the agent's login")
