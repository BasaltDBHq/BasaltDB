package privdrop

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// The drop is irreversible, so it runs in a child: the test binary, copied
// into a root-owned directory (the binary check refuses one under /tmp), run
// again with childEnv set.
const (
	childEnv  = "BASALT_PRIVDROP_CHILD"
	baseEnv   = "BASALT_PRIVDROP_BASE"
	childOK   = "PRIVDROP-CHILD-OK"
	dropUser  = "nobody"
	threads   = 16
	secretTxt = "secret"
)

// TestDropEveryThread is the Linux integration test of basalt engine
// --user: as root (make test-privdrop runs it in a container without
// systemd), a process with many OS threads drops to nobody, and every
// thread, including one made after the drop, must have changed ids, no
// capabilities and no_new_privs; root cannot be taken back, and a file only
// root may read stays closed.
func TestDropEveryThread(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		dropChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: run make test-privdrop (Docker, a Linux container without systemd)")
	}
	base, err := os.MkdirTemp("/run", "basalt-privdrop-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	require.NoError(t, os.Chmod(base, 0o755))

	self, err := os.Executable()
	require.NoError(t, err)
	bin := filepath.Join(base, "privdrop.test")
	copyFile(t, self, bin, 0o755)
	require.NoError(t, os.WriteFile(filepath.Join(base, secretTxt), []byte("credential\n"), 0o600))

	cmd := exec.Command(bin, "-test.run=^TestDropEveryThread$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"=1", baseEnv+"="+base)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child:\n%s", out)
	require.Contains(t, string(out), childOK, "child:\n%s", out)

	for _, d := range testDirs(base) {
		fi, err := os.Stat(d.Path)
		require.NoError(t, err)
		require.Equal(t, d.Mode, fi.Mode().Perm(), d.Path)
		st, ok := fi.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		nobody, err := OS{}.Lookup(dropUser)
		require.NoError(t, err)
		require.Equal(t, nobody.UID, st.Uid, d.Path)
	}
}

func testDirs(base string) []Dir {
	return []Dir{{Path: filepath.Join(base, "run"), Mode: 0o755}, {Path: filepath.Join(base, "state"), Mode: 0o700}}
}

// dropChild runs as root in the child process.
func dropChild(t *testing.T) {
	base := os.Getenv(baseEnv)
	require.NotEmpty(t, base)

	// Hold several goroutines on their own OS threads so the drop has
	// threads besides the one calling it.
	release := make(chan struct{})
	ready := make(chan struct{})
	for range threads {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-release
		}()
	}
	for range threads {
		<-ready
	}
	defer close(release)
	before, err := os.ReadDir(taskDir)
	require.NoError(t, err)
	require.Greater(t, len(before), threads, "the child runs on many threads")

	res, err := Drop(OS{Executable: filepath.Join(base, "privdrop.test")}, dropUser, testDirs(base))
	require.NoError(t, err)
	require.True(t, res.Dropped)

	// Verify ran inside Drop; check again independently, and on a thread
	// made after the drop.
	require.NoError(t, verifyThreads(taskDir, res.Account))
	// Threads made after the drop (the ones before are all held) inherit it.
	done := make(chan error)
	for range threads / 4 {
		go func() {
			runtime.LockOSThread() // a locked goroutine that exits takes its thread with it
			raw, err := os.ReadFile("/proc/thread-self/status")
			if err == nil {
				var st threadStatus
				if st, err = parseStatus(string(raw)); err == nil {
					err = st.check(res.Account)
				}
			}
			done <- err
		}()
	}
	for range threads / 4 {
		require.NoError(t, <-done)
	}

	require.Equal(t, int(res.Account.UID), os.Getuid())
	require.Equal(t, int(res.Account.UID), os.Geteuid())
	require.True(t, errors.Is(syscall.Setuid(0), syscall.EPERM), "setuid(0) must fail")
	require.True(t, errors.Is(syscall.Setgid(0), syscall.EPERM), "setgid(0) must fail")
	require.Error(t, syscall.Setgroups([]int{0}), "setgroups must fail")
	_, err = os.ReadFile(filepath.Join(base, secretTxt))
	require.ErrorIs(t, err, os.ErrPermission, "root's 0600 file stays closed")

	// The state directory is the engine's to write; the umask keeps what it
	// makes there private.
	f := filepath.Join(base, "state", "head.json")
	require.NoError(t, os.WriteFile(f, []byte("{}"), 0o666))
	fi, err := os.Stat(f)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	fmt.Println(childOK)
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	src, err := os.Open(from)
	require.NoError(t, err)
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	require.NoError(t, err)
	_, err = io.Copy(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.Close())
	require.NoError(t, os.Chmod(to, mode))
}

// The status of a real thread parses, whoever runs the test.
func TestParseOwnStatus(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/status")
	require.NoError(t, err)
	st, err := parseStatus(string(raw))
	require.NoError(t, err)
	require.Len(t, st.UIDs, idFields)
	require.Equal(t, uint32(os.Getuid()), st.UIDs[0])
	require.True(t, strings.Contains(string(raw), "NoNewPrivs:"))
}
