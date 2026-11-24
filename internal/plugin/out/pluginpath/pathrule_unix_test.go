//go:build unix

package pluginpath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// fakeDir is a directory's status as Lstat would give it, for owners and
// modes a test cannot make without root.
type fakeDir struct {
	mode     fs.FileMode
	uid, gid uint32
}

func (f fakeDir) Name() string       { return "d" }
func (f fakeDir) Size() int64        { return 0 }
func (f fakeDir) Mode() fs.FileMode  { return f.mode }
func (f fakeDir) ModTime() time.Time { return time.Time{} }
func (f fakeDir) IsDir() bool        { return f.mode.IsDir() }
func (f fakeDir) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid} }

// The socket base's exception, judged from an injected status (no test
// runs as root, so it cannot make a root-owned directory): a directory
// others can write passes only when root owns it and its sticky bit is
// set; the plugin root's rule makes no exception for it.
func TestSocketBaseStickyRootException(t *testing.T) {
	t.Parallel()
	me, err := CurrentUID()
	require.NoError(t, err)
	if me == pluginmodel.RootUID {
		t.Skip("the cases need an owner that is not root")
	}
	sticky := abovePolicy{stickyRoot: true}
	// A real directory with no ACL: the status is injected, the ACL is read.
	base := t.TempDir()
	for _, tc := range []struct {
		name string
		fi   fakeDir
		ok   bool
		why  string
	}{
		{"root, sticky, 1777", fakeDir{fs.ModeDir | fs.ModeSticky | 0o777, pluginmodel.RootUID, 0}, true, ""},
		{"root, sticky, group-writable 1775", fakeDir{fs.ModeDir | fs.ModeSticky | 0o775, pluginmodel.RootUID, 0}, true, ""},
		{"root, no sticky bit, 0777", fakeDir{fs.ModeDir | 0o777, pluginmodel.RootUID, 0}, false, pluginmodel.WhyNotStickyRoot},
		{"the engine's user, sticky, 1777", fakeDir{fs.ModeDir | fs.ModeSticky | 0o777, me, 0}, false, pluginmodel.WhyNotStickyRoot},
		{"another user, sticky, 1777", fakeDir{fs.ModeDir | fs.ModeSticky | 0o777, me + 1, 0}, false, "is owned by a user other than root"},
		{"root, 0755", fakeDir{fs.ModeDir | 0o755, pluginmodel.RootUID, 0}, true, ""},
	} {
		err := checkAboveInfo(base, tc.fi, me, sticky)
		if tc.ok {
			require.NoError(t, err, tc.name)
		} else {
			require.ErrorContains(t, err, tc.why, tc.name)
			var ve *pluginmodel.VerifyError
			require.True(t, errors.As(err, &ve), tc.name)
			require.NotNil(t, ve.Path, tc.name)
		}
		// The plugin root and the trust store take no exception.
		if tc.fi.mode.Perm()&groupOtherWrite != 0 {
			require.Error(t, checkAboveInfo(base, tc.fi, me, abovePolicy{}), tc.name)
		}
	}
}

// A resolved root-owned sticky /tmp (Linux; /private/tmp behind a root-owned
// link on macOS) passes the socket base rule, and still fails the path
// rule plugins and keys are checked with. Only status is read.
func TestStockTmpIsASocketBase(t *testing.T) {
	t.Parallel()
	resolved, err := filepath.EvalSymlinks("/tmp")
	require.NoError(t, err)
	fi, err := os.Lstat(resolved)
	require.NoError(t, err)
	uid, err := fileOwner(fi)
	require.NoError(t, err)
	if uid != pluginmodel.RootUID || fi.Mode()&fs.ModeSticky == 0 || fi.Mode().Perm()&0o002 == 0 {
		t.Skipf("%s is not a world-writable sticky directory of root's here", resolved)
	}
	me, err := CurrentUID()
	require.NoError(t, err)
	require.NoError(t, CheckSocketBase("/tmp"))
	require.NoError(t, CheckSocketBaseInfo(resolved, fi))
	err = CheckAbove("/tmp/plugins", me)
	require.ErrorContains(t, err, pluginmodel.WhyGroupWritable)
	var ve *pluginmodel.VerifyError
	require.True(t, errors.As(err, &ve))
	require.Equal(t, pluginmodel.PathWritable, ve.Path.Kind)
	require.Equal(t, uint32(pluginmodel.RootUID), ve.Path.UID)
}

// Path rule refusals carry what was found: the kind, owner, group and mode.
func TestPathRuleRefusalsNameTheFault(t *testing.T) {
	t.Parallel()
	me, err := CurrentUID()
	require.NoError(t, err)
	dir := t.TempDir()

	writable := filepath.Join(dir, "w")
	require.NoError(t, os.Mkdir(writable, 0o755))
	require.NoError(t, os.Chmod(writable, 0o775))
	_, err = CheckStrict(writable, me)
	var ve *pluginmodel.VerifyError
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Equal(t, &pluginmodel.PathFault{Kind: pluginmodel.PathWritable, UID: me, GID: ve.Path.GID, Mode: uint32(fs.ModeDir | 0o775), Owners: []uint32{me}}, ve.Path)

	link := filepath.Join(dir, "l")
	require.NoError(t, os.Symlink(writable, link))
	_, err = CheckStrict(link, me)
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Equal(t, pluginmodel.PathSymlink, ve.Path.Kind)

	// A wrong owner: as for root, judged from an injected status.
	err = CheckStrictInfo("/x", fakeDir{fs.ModeDir | 0o755, me + 1, 0}, me)
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Equal(t, pluginmodel.PathOwner, ve.Path.Kind)
	require.Equal(t, me+1, ve.Path.UID)
	require.Equal(t, []uint32{me}, ve.Path.Owners)

	// An I/O failure is no path fault.
	_, err = CheckStrict(filepath.Join(dir, "missing"), me)
	require.True(t, errors.As(err, &ve), "%v", err)
	require.Nil(t, ve.Path)
}
