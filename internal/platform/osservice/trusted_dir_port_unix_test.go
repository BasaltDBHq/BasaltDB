//go:build unix

package osservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// OpenTrustedDirPort hands back the directory OpenTrustedDir opened, and on
// a refusal no directory at all: a nil interface, never a nil *TrustedDir
// inside one, so a caller's nil check holds.
func TestOpenTrustedDirPort(t *testing.T) {
	dir := realTempDir(t)
	d, err := OpenTrustedDirPort(dir, keepID, false)
	require.NoError(t, err)
	require.NotNil(t, d)
	require.Equal(t, dir, d.Path())
	require.NoError(t, d.Close())

	d, err = OpenTrustedDirPort(filepath.Join(dir, "missing"), keepID, false)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.True(t, d == nil, "a refusal is a nil interface, not a typed nil")
}
