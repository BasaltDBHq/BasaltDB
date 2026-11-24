//go:build unix

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// Split so no scanner takes the fixture for a real connection string.
const readCredDSN = "postgres://bot" + ":pw@db.example.com/app"

func writeCred(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(readCredDSN+"\n"), 0o600))
	require.NoError(t, os.Chmod(path, mode))
}

func TestReadCredentialReadsAPlainOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.url")
	writeCred(t, path, 0o600)

	dsn, err := config.ReadCredential(path)

	require.NoError(t, err)
	require.Equal(t, readCredDSN, dsn)
}

func TestReadCredentialRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.url")
	writeCred(t, target, 0o600)
	link := filepath.Join(dir, "bot.url")
	require.NoError(t, os.Symlink(target, link))

	dsn, err := config.ReadCredential(link)

	require.Empty(t, dsn)
	require.ErrorContains(t, err, "credential file "+link+" is a symbolic link")
	require.NotContains(t, err.Error(), readCredDSN)
	require.NotErrorIs(t, err, os.ErrNotExist)
}

// A dangling symlink is refused too, not taken for a missing file that a
// repair would write through the link.
func TestReadCredentialRefusesADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "bot.url")
	require.NoError(t, os.Symlink(filepath.Join(dir, "gone"), link))

	_, err := config.ReadCredential(link)

	require.ErrorContains(t, err, "is a symbolic link")
	require.NotErrorIs(t, err, os.ErrNotExist)
}

func TestReadCredentialRefusesAHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bot.url")
	writeCred(t, path, 0o600)
	require.NoError(t, os.Link(path, filepath.Join(dir, "other.url")))

	dsn, err := config.ReadCredential(path)

	require.Empty(t, dsn)
	require.ErrorContains(t, err, "credential file "+path+": file has more than one hard link")
}

func TestReadCredentialRefusesADirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.url")
	require.NoError(t, os.Mkdir(path, 0o700))

	_, err := config.ReadCredential(path)

	require.ErrorContains(t, err, "credential file "+path+": not a regular file")
}

func TestReadCredentialKeepsItsModeAndEmptyTexts(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.url")
	writeCred(t, open, 0o644)
	_, err := config.ReadCredential(open)
	require.EqualError(t, err, "credential file "+open+" is mode 644; it must be readable by the engine's user only (0600)")

	empty := filepath.Join(dir, "empty.url")
	require.NoError(t, os.WriteFile(empty, []byte(" \n"), 0o600))
	_, err = config.ReadCredential(empty)
	require.EqualError(t, err, "credential file "+empty+" is empty")
}

// A missing file stays fs.ErrNotExist: the setup page's REPAIR writes a new
// credential when the file is gone.
func TestReadCredentialMissingIsNotExist(t *testing.T) {
	_, err := config.ReadCredential(filepath.Join(t.TempDir(), "bot.url"))

	require.ErrorIs(t, err, os.ErrNotExist)
}
