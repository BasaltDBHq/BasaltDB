package main

import "os"

// fullRun reports whether BASALTDB_TEST_FULL=1 is set. The classify CLI tests
// run on a smaller copy of the fixture by default and on the whole fixture
// with the flag; the nightly job sets it (see .github/workflows/nightly-full.yml).
func fullRun() bool { return os.Getenv("BASALTDB_TEST_FULL") == "1" }

// fixtureRows is how many customers the classify fixture keeps: all 200 with
// BASALTDB_TEST_FULL=1, 12 otherwise. Every classify run parses each
// phone-shaped value, so the number of rows is what makes the tests slow under -race.
func fixtureRows() int {
	if fullRun() {
		return 200
	}
	return 12
}
