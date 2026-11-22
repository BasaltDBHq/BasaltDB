package pii_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

func tokenID(t *testing.T, k *pii.Keys) string {
	t.Helper()
	tok, err := k.MakeToken(pii.EntityPersonName, "Alice Tamm", "")
	require.NoError(t, err)
	return tok.ID
}

func TestLoadKeysCreatesA0600KeyOnFirstStartAndReusesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), pii.KeyFileName)
	k1, err := pii.LoadKeys(path, rand.Reader)
	require.NoError(t, err)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, int64(pii.MasterKeySize), fi.Size())
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temp file left behind")

	k2, err := pii.LoadKeys(path, rand.Reader)
	require.NoError(t, err)
	require.Equal(t, tokenID(t, k1), tokenID(t, k2), "the same key file gives the same tokens")
}

func TestLoadKeysUsesTheFileBytesAsTheMaster(t *testing.T) {
	path := filepath.Join(t.TempDir(), pii.KeyFileName)
	require.NoError(t, os.WriteFile(path, testMaster, 0o600))
	k, err := pii.LoadKeys(path, rand.Reader)
	require.NoError(t, err)
	require.Equal(t, tokenID(t, newKeys(t, testMaster)), tokenID(t, k))
}

func TestLoadKeysRefusesAWideMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		path := filepath.Join(t.TempDir(), pii.KeyFileName)
		require.NoError(t, os.WriteFile(path, testMaster, 0o600))
		require.NoError(t, os.Chmod(path, mode))
		_, err := pii.LoadKeys(path, rand.Reader)
		require.ErrorContains(t, err, "0600", mode)
		require.NotContains(t, err.Error(), string(testMaster))
	}
}

func TestLoadKeysRefusesAWrongSize(t *testing.T) {
	for _, n := range []int{0, 16, 33} {
		path := filepath.Join(t.TempDir(), pii.KeyFileName)
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{1}, n), 0o600))
		_, err := pii.LoadKeys(path, rand.Reader)
		require.Error(t, err, n)
	}
}

func TestLoadKeysRefusesASymlinkOrADirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.WriteFile(target, testMaster, 0o600))
	link := filepath.Join(dir, pii.KeyFileName)
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	_, err := pii.LoadKeys(link, rand.Reader)
	require.ErrorContains(t, err, "regular file")

	sub := filepath.Join(t.TempDir(), pii.KeyFileName)
	require.NoError(t, os.Mkdir(sub, 0o700))
	_, err = pii.LoadKeys(sub, rand.Reader)
	require.ErrorContains(t, err, "regular file")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestLoadKeysLeavesNoFileWhenRandomnessFails(t *testing.T) {
	dir := t.TempDir()
	_, err := pii.LoadKeys(filepath.Join(dir, pii.KeyFileName), failingReader{})
	require.Error(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}
