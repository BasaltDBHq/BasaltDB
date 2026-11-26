//go:build unix

package dictfile

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

func TestLoadKeysRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), pii.KeyFileName)
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	done := make(chan error, 1)
	go func() {
		_, err := LoadKeys(path, rand.Reader)
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("LoadKeys blocked on a FIFO")
	}
}

func TestLoadKeysRefusesASecondHardLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), pii.KeyFileName)
	require.NoError(t, os.WriteFile(path, make([]byte, pii.MasterKeySize), 0o600))
	other := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.Link(path, other))
	_, err := LoadKeys(path, rand.Reader)
	require.ErrorContains(t, err, "more than one hard link")
	require.NoError(t, os.Remove(other))
	_, err = LoadKeys(path, rand.Reader)
	require.NoError(t, err)
}

func TestLoadKeysRefusesAnotherOwnersFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown needs root; ownerfile's tests prove the owner rule")
	}
	path := filepath.Join(t.TempDir(), pii.KeyFileName)
	require.NoError(t, os.WriteFile(path, make([]byte, pii.MasterKeySize), 0o600))
	require.NoError(t, os.Chown(path, 4242, 4242))
	_, err := LoadKeys(path, rand.Reader)
	require.ErrorContains(t, err, "owned by uid 4242")
}
