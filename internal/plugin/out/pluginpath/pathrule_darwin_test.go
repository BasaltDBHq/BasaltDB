package pluginpath

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// addACL adds a macOS ACL entry to path and strips every entry at cleanup,
// so TempDir can remove it.
func addACL(t *testing.T, path, entry string) {
	t.Helper()
	out, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

// An ACL entry that lets others write a directory fails the path rule as a
// group- or other-writable mode does, at a root and above it, though the
// mode stays 0755. A deny entry, as macOS puts on every home directory,
// still passes.
func TestPathRuleCountsACLs(t *testing.T) {
	t.Parallel()
	me, err := CurrentUID()
	require.NoError(t, err)

	refusedForACL := func(t *testing.T, err error, p string) {
		t.Helper()
		require.ErrorContains(t, err, pluginmodel.WhyACLWritable)
		var ve *pluginmodel.VerifyError
		require.True(t, errors.As(err, &ve), "%v", err)
		require.Equal(t, p, ve.File)
		require.NotNil(t, ve.Path)
		require.Equal(t, pluginmodel.PathWritable, ve.Path.Kind)
	}

	t.Run("at a root", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "plugins")
		require.NoError(t, os.Mkdir(dir, 0o755))
		_, err := CheckStrict(dir, me)
		require.NoError(t, err)
		addACL(t, dir, "everyone allow add_file,add_subdirectory,delete_child")
		_, err = CheckStrict(dir, me)
		refusedForACL(t, err, dir)
	})

	t.Run("a file at a root", func(t *testing.T) {
		t.Parallel()
		f := filepath.Join(t.TempDir(), "bin")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o755))
		addACL(t, f, "everyone allow write")
		_, err := CheckStrict(f, me)
		refusedForACL(t, err, f)
	})

	t.Run("above a root", func(t *testing.T) {
		t.Parallel()
		tmp, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		config := filepath.Join(tmp, "config")
		require.NoError(t, os.Mkdir(config, 0o755))
		root := filepath.Join(config, "plugins")
		require.NoError(t, CheckAbove(root, me))
		addACL(t, config, "everyone allow add_subdirectory")
		refusedForACL(t, CheckAbove(root, me), config)
	})

	t.Run("deny and read entries pass", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "plugins")
		require.NoError(t, os.Mkdir(dir, 0o755))
		addACL(t, dir, "group:everyone deny delete")
		addACL(t, dir, "everyone allow list,search")
		_, err := CheckStrict(dir, me)
		require.NoError(t, err)
		require.NoError(t, CheckAbove(filepath.Join(dir, "x"), me))
	})
}
