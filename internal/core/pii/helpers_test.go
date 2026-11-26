package pii_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// fullRun reports whether the exhaustive sizes are wanted: set
// BASALTDB_TEST_FULL=1 to run every case at its full size. The default path
// runs smaller, sampled loops so a race-enabled run stays short.
func fullRun() bool { return os.Getenv("BASALTDB_TEST_FULL") == "1" }

// sized is full when fullRun, light otherwise.
func sized(full, light int) int {
	if fullRun() {
		return full
	}
	return light
}

// testMaster is a fixed 32-byte master key for tests only.
var testMaster = []byte("test-master-key-0123456789abcdef")

func newKeys(t testing.TB, master []byte) *pii.Keys {
	t.Helper()
	k, err := pii.NewKeys(master)
	require.NoError(t, err)
	return k
}
