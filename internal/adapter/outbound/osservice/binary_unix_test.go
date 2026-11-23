//go:build unix

package osservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A basalt the test user built and owns is refused with the fix.
func TestOSSystemCheckBinaryRefusesUserOwnedBinary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root the test file is root's")
	}
	bin := filepath.Join(t.TempDir(), "basalt")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))

	err := OSSystem{}.CheckBinary(bin)
	require.ErrorContains(t, err, "not root")
	require.ErrorContains(t, err, "sudo install -o root -m 0755 "+bin+" /usr/local/libexec/basalt")
}

// A system binary is root's on every unix: it passes, through the /bin ->
// usr/bin link on Linux too.
func TestOSSystemCheckBinaryAcceptsSystemBinary(t *testing.T) {
	require.NoError(t, OSSystem{}.CheckBinary("/bin/sh"))
}
