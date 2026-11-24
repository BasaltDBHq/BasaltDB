//go:build unix

package keyfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

func TestLoadKeysRefusesAFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), channel.KeyFileName)
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	done := make(chan error, 1)
	go func() {
		_, err := LoadOrCreateKeys(path, time.Now)
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, channel.ErrKeyFile)
		require.ErrorContains(t, err, "regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("LoadOrCreateKeys blocked on a FIFO")
	}
}

// statInfo is an os.FileInfo whose owner is set by the test.
type statInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (s statInfo) Sys() any { return s.st }

func TestCheckOwnerRefusesAnotherUser(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), channel.KeyFileName)
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, checkOwner(fi), "the file this process wrote is its own")

	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	require.ErrorContains(t, checkOwner(statInfo{FileInfo: fi, st: &st}), "not by the engine's user")
}

func TestCheckStateDirRefusesAnotherUsersDirectory(t *testing.T) {
	t.Parallel()
	fi, err := os.Lstat(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, checkStateDirInfo(fi))
	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	require.ErrorContains(t, checkStateDirInfo(statInfo{FileInfo: fi, st: &st}), "not by the engine's user")
}
