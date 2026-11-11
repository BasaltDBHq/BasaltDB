//go:build unix

package pii

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadKeysRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), KeyFileName)
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

// statInfo is an os.FileInfo whose owner is set by the test.
type statInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (s statInfo) Sys() any { return s.st }

func TestCheckOwnerRefusesAnotherUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), KeyFileName)
	require.NoError(t, os.WriteFile(path, make([]byte, MasterKeySize), 0o600))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, checkOwner(fi), "the file this process wrote is its own")

	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	require.ErrorContains(t, checkOwner(statInfo{FileInfo: fi, st: &st}), "not by the engine's user")
}
