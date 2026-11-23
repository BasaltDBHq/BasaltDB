package pii

import "os"

// sized is full when BASALTDB_TEST_FULL=1 is set, light otherwise: the
// default path runs fewer rounds of the property tests.
func sized(full, light int) int {
	if os.Getenv("BASALTDB_TEST_FULL") == "1" {
		return full
	}
	return light
}
