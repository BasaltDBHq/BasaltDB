//go:build unix

package engineos

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsurePrivateDirsRecreates(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "a", "run")

	require.NoError(t, OS{}.MakePrivateDirs(os.Geteuid(), 0o700, d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}

func TestEnsurePrivateDirsTightens(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.Mkdir(d, 0o755))
	require.NoError(t, os.Chmod(d, 0o755))
	inside := filepath.Join(d, "pii.key")
	require.NoError(t, os.WriteFile(inside, []byte("k"), 0o600))

	require.NoError(t, OS{}.MakePrivateDirs(os.Geteuid(), 0o700, d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	fi, err = os.Stat(inside)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "what is inside is not touched")
}

// A folder another user owns is not ours to change.
func TestEnsurePrivateDirsLeavesOthers(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(d, 0o755))
	require.NoError(t, os.Chmod(d, 0o755))

	require.NoError(t, OS{}.MakePrivateDirs(os.Geteuid()+1, 0o700, d))

	fi, err := os.Stat(d)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
}

func TestEnsurePrivateDirsRefusesSymlink(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.Chmod(target, 0o755))
	link := filepath.Join(base, "run")
	require.NoError(t, os.Symlink(target, link))

	err := OS{}.MakePrivateDirs(os.Geteuid(), 0o700, link)

	require.ErrorContains(t, err, "not a plain directory")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "what it points at is not changed")
}

// A dangling symlink is named for what it is, not as a failed mkdir.
func TestEnsurePrivateDirsRefusesADanglingSymlink(t *testing.T) {
	t.Parallel()
	link := filepath.Join(t.TempDir(), "run")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "nowhere"), link))
	require.ErrorContains(t, OS{}.MakePrivateDirs(os.Geteuid(), 0o700, link), "not a plain directory")
}
