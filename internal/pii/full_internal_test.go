package pii

import "os"

// fullRun reports whether the exhaustive sizes are wanted: set
// BASALTDB_TEST_FULL=1 to run every case at its full size.
func fullRun() bool { return os.Getenv("BASALTDB_TEST_FULL") == "1" }

// sized is full when fullRun, light otherwise.
func sized(full, light int) int {
	if fullRun() {
		return full
	}
	return light
}
