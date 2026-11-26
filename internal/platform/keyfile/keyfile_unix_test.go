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

func TestLoadOrCreateKeysRefusesASecondHardLinkAndLeavesIt(t *testing.T) {
	t.Parallel()
	path, _ := writeValid(t)
	other := filepath.Join(t.TempDir(), "elsewhere")
	require.NoError(t, os.Link(path, other))
	_, err := LoadOrCreateKeys(path, time.Now)
	require.ErrorIs(t, err, channel.ErrKeyFile)
	require.ErrorContains(t, err, "more than one hard link")
	_, err = os.Lstat(other)
	require.NoError(t, err, "the refused file is left as it is")
	require.NoError(t, os.Remove(other))
	_, err = LoadOrCreateKeys(path, time.Now)
	require.NoError(t, err)
}

func TestLoadOrCreateKeysRefusesAFIFOWithoutBlocking(t *testing.T) {
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

func TestCheckStateDirRefusesAnotherUsersDirectory(t *testing.T) {
	t.Parallel()
	fi, err := os.Lstat(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, checkStateDirInfo(fi))
	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	require.ErrorContains(t, checkStateDirInfo(statInfo{FileInfo: fi, st: &st}), "not this process's user")
}
