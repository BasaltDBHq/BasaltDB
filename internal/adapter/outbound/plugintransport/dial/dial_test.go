//go:build unix

package dial

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// A socket plugin that exits without listening is refused, and its socket
// directory is gone.
func TestSocketPluginThatNeverListens(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	v := pluginhost.Verified{Dir: "/", Manifest: pluginhost.Manifest{Endpoint: pluginhost.Endpoint{Local: &pluginhost.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	k := pluginhost.EntryKey{Name: "acme-ner", Instance: "default"}
	_, err := Entry(ctx, k, v, Options{SocketBase: base})
	require.True(t, errors.Is(err, ErrNoSocket), "%v", err)
	require.Contains(t, err.Error(), "plugin acme-ner/default")
	left, err := os.ReadDir(base)
	require.NoError(t, err)
	require.Empty(t, left)
}

// A socket base too long for a Unix socket path is refused before anything
// starts, with the rule.
func TestSocketPathTooLong(t *testing.T) {
	t.Parallel()
	base := filepath.Join(shortBase(t), strings.Repeat("d", MaxSocketPath))
	v := pluginhost.Verified{Dir: "/", Manifest: pluginhost.Manifest{Endpoint: pluginhost.Endpoint{Local: &pluginhost.LocalEndpoint{Transport: TransportConnect, Command: "usr/bin/true"}}}}
	_, err := Entry(context.Background(), pluginhost.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base})
	require.ErrorContains(t, err, "Unix sockets take at most")
}

// TestMain: run as a socket plugin (SocketEnv set), the test binary listens
// on its socket and reads until it is killed.
func TestMain(m *testing.M) {
	if sock := os.Getenv(SocketEnv); sock != "" {
		l, err := net.Listen("unix", sock)
		if err != nil {
			os.Exit(2)
		}
		for {
			c, err := l.Accept()
			if err != nil {
				os.Exit(0)
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}
	os.Exit(m.Run())
}

// A socket base that group or others can write is refused before anything
// starts or is made, with the fix, unless root owns it and its sticky bit
// is set: a sticky directory the test's user owns is refused too.
func TestSocketBaseOthersCanWriteIsRefused(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("a directory root owns is the exception")
	}
	for _, mode := range []os.FileMode{0o777, 0o770, 0o1777, 0o1770} {
		base := shortBase(t)
		require.NoError(t, os.Chmod(base, mode))
		v := pluginhost.Verified{Dir: "/", Manifest: pluginhost.Manifest{Endpoint: pluginhost.Endpoint{Local: &pluginhost.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
		_, err := Entry(context.Background(), pluginhost.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base})
		require.ErrorContains(t, err, pluginhost.WhyNotStickyRoot, "mode %o", mode)
		require.ErrorContains(t, err, "Set TMPDIR")
		require.NotContains(t, err.Error(), "chmod")
		left, err := os.ReadDir(base)
		require.NoError(t, err)
		require.Empty(t, left, "mode %o: nothing made", mode)
	}
}

// With Runs set, a socket plugin's start is recorded with its socket
// directory until it is closed.
func TestSocketPluginIsRecorded(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	runs := filepath.Join(shortBase(t), "runs")
	v := pluginhost.Verified{Dir: "/", Manifest: pluginhost.Manifest{Endpoint: pluginhost.Endpoint{Local: &pluginhost.LocalEndpoint{Transport: TransportUnix, Command: "usr/bin/true"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// It never listens, so the start fails after the process was recorded;
	// the failed start stops it and drops the record.
	_, err := Entry(ctx, pluginhost.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base, Runs: &child.Runs{Dir: runs}})
	require.ErrorIs(t, err, ErrNoSocket)
	recs, err := os.ReadDir(runs)
	require.NoError(t, err, "the start was recorded")
	require.Empty(t, recs, "and the record dropped when it stopped")
}

// Anything already at the socket directory's name (a directory, a file, a
// symlink another user could plant) fails the start, is left as it is, and
// nothing is made.
func TestSocketDirNameTakenIsRefused(t *testing.T) {
	t.Parallel()
	for _, plant := range []string{"dir", "file", "symlink"} {
		base := shortBase(t)
		target := shortBase(t)
		name := "bp00112233445566"
		at := filepath.Join(base, name)
		switch plant {
		case "dir":
			require.NoError(t, os.Mkdir(at, 0o755))
		case "file":
			require.NoError(t, os.WriteFile(at, []byte("x"), 0o644))
		case "symlink":
			require.NoError(t, os.Symlink(target, at))
		}
		before, err := os.Lstat(at)
		require.NoError(t, err)
		err = makeSocketDir(base, name)
		require.ErrorContains(t, err, "already exists", plant)
		after, err := os.Lstat(at)
		require.NoError(t, err, plant)
		require.Equal(t, before.Mode(), after.Mode(), plant)
		require.True(t, os.SameFile(before, after), plant)
		left, err := os.ReadDir(base)
		require.NoError(t, err)
		require.Len(t, left, 1, "%s: nothing else made", plant)
		inTarget, err := os.ReadDir(target)
		require.NoError(t, err)
		require.Empty(t, inTarget, "%s: nothing made through the link", plant)
	}
}

// The directory made is the engine user's, mode 0700, with a random name
// of the stated length, new at each start.
func TestSocketDirIsPrivate(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	dir, sock, err := socketDir(base)
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(base)
	require.NoError(t, err)
	require.Equal(t, resolved, filepath.Dir(dir))
	require.Equal(t, filepath.Join(dir, socketFile), sock)
	require.Regexp(t, `^bp[0-9a-f]{16}$`, filepath.Base(dir))
	fi, err := os.Lstat(dir)
	require.NoError(t, err)
	require.True(t, fi.IsDir())
	require.Equal(t, fs.FileMode(0o700), fi.Mode().Perm())
	require.Equal(t, uint32(os.Geteuid()), fi.Sys().(*syscall.Stat_t).Uid)
	other, _, err := socketDir(base)
	require.NoError(t, err)
	require.NotEqual(t, dir, other, "a new name each start")
}

// With TMPDIR unset on Linux, a socket plugin starts in a socket directory
// under the stock /tmp: root's, world-writable, with the sticky bit set.
// Not parallel: it unsets TMPDIR for the whole process.
func TestSocketPluginStartsUnderDefaultTmp(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the stock /tmp case is Linux's; macOS sets TMPDIR to a private directory")
	}
	if os.Geteuid() == 0 {
		t.Skip("as root every directory root owns passes; the case is a plain user's")
	}
	fi, err := os.Lstat("/tmp")
	require.NoError(t, err)
	st := fi.Sys().(*syscall.Stat_t)
	require.True(t, st.Uid == 0 && fi.Mode()&fs.ModeSticky != 0 && fi.Mode().Perm()&0o002 != 0,
		"/tmp here is not a stock /tmp (root's, mode 1777): %v uid %d", fi.Mode(), st.Uid)
	t.Setenv("TMPDIR", "")
	require.Equal(t, "/tmp", os.TempDir())
	startListeningPlugin(t, "", "/tmp")
}

// The plugin TestMain serves starts and is reached in a private base too,
// on every OS: the harness the /tmp case uses works.
func TestSocketPluginStartsUnderAPrivateBase(t *testing.T) {
	t.Parallel()
	base := shortBase(t)
	resolved, err := filepath.EvalSymlinks(base)
	require.NoError(t, err)
	startListeningPlugin(t, base, resolved)
}

// startListeningPlugin starts this test binary as a jsonrpc-unix plugin
// with socket base base, checks its socket directory is a 0700 directory
// in want, and that closing it removes the directory.
func startListeningPlugin(t *testing.T, base, want string) {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	exe, err = filepath.EvalSymlinks(exe)
	require.NoError(t, err)
	v := pluginhost.Verified{Dir: filepath.Dir(exe), Manifest: pluginhost.Manifest{Endpoint: pluginhost.Endpoint{Local: &pluginhost.LocalEndpoint{Transport: TransportUnix, Command: filepath.Base(exe)}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tr, err := Entry(ctx, pluginhost.EntryKey{Name: "acme-ner", Instance: "default"}, v, Options{SocketBase: base})
	require.NoError(t, err)
	started, ok := tr.(*socketTransport)
	require.True(t, ok)
	require.Equal(t, want, filepath.Dir(started.dir))
	dfi, err := os.Lstat(started.dir)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), dfi.Mode().Perm())
	require.NoError(t, tr.Close())
	_, err = os.Lstat(started.dir)
	require.True(t, errors.Is(err, fs.ErrNotExist), "removed when the plugin stops: %v", err)
}

// shortBase is a new directory short enough for socket paths (t.TempDir is
// too long on macOS).
func shortBase(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
