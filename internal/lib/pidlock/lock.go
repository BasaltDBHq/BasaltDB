// Package pidlock is the engine's pidfile lock: one exclusive flock held for
// the server's lifetime, and a probe for whether one is held.
package pidlock

import "fmt"

// dataDirPermMode is the mode for the pidfile's directory when it is created.
const dataDirPermMode = 0o755

// AlreadyRunningError is returned when another process holds the pidfile lock.
type AlreadyRunningError struct {
	PID     int
	PIDFile string
}

func (e *AlreadyRunningError) Error() string {
	return fmt.Sprintf("already running (pid %d, %s)", e.PID, e.PIDFile)
}
