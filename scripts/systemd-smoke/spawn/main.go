// Command spawn stands in for the engine under the engine's own service
// sandbox: it writes a program into the engine's state directory, starts it
// as a child the way the engine starts a local plugin (its own process group,
// its copy as the working directory, only BASALT_PLUGIN_SOCKET in its
// environment), and reaches it on two Unix sockets: one in a directory it
// makes under the OS temporary directory, as the engine does for a plugin in
// same-user mode, and one in a directory the child makes under the state
// directory. The child is this same binary, run with -child.
//
// The smoke test runs it in a transient unit with the engine unit's sandbox
// settings (scripts/systemd-smoke/smoke.sh); on macOS it can be run by hand
// as the engine's OS user. Every line it prints starts with "spawn ".
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	socketEnv  = "BASALT_PLUGIN_SOCKET"
	privateDir = 0o700
	reachWait  = 10 * time.Second
	otherWrite = 0o002

	mountPointField = 4
	mountOptsField  = 5
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	child := fs.Bool("child", false, "run as the started program: listen on both sockets")
	stateSock := fs.String("state-socket", "", "with -child: the socket to make under the state directory")
	state := fs.String("state", "", "the engine's state directory")
	marker := fs.String("marker", "", "a file the smoke test made in the host's /tmp (Linux; optional)")
	readOnly := fs.String("read-only", "", "a directory the sandbox must not let it write (Linux; optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *child {
		return serveChild(os.Getenv(socketEnv), *stateSock)
	}
	if *state == "" {
		_, _ = fmt.Fprintln(out, "spawn: needs -state")
		return 2
	}
	r := &report{out: out}
	r.parent(*state, *marker, *readOnly)
	_, _ = fmt.Fprintln(out, "spawn done")
	if r.failed > 0 {
		return 1
	}
	return 0
}

type report struct {
	out    io.Writer
	failed int
}

func (r *report) ok(name, what string) { _, _ = fmt.Fprintf(r.out, "spawn ok %s: %s\n", name, what) }

func (r *report) fail(name, what string) {
	r.failed++
	_, _ = fmt.Fprintf(r.out, "spawn FAIL %s: %s\n", name, what)
}

func (r *report) check(name string, good bool, what string) {
	if good {
		r.ok(name, what)
		return
	}
	r.fail(name, what)
}

func (r *report) parent(state, marker, readOnly string) {
	r.ok("runs-as", fmt.Sprintf("uid %d gid %d", os.Getuid(), os.Getgid()))
	r.sandboxEvidence(state, marker, readOnly)

	copyDir, err := writeCopy(state)
	if err != nil {
		r.fail("write-copy", err.Error())
		return
	}
	defer os.RemoveAll(filepath.Dir(copyDir))
	r.ok("write-copy", "wrote an executable copy at "+filepath.Join(copyDir, "bin", "child"))

	tmp := os.TempDir()
	if fi, err := os.Stat(tmp); err == nil {
		st, _ := fi.Sys().(*syscall.Stat_t)
		// The same-user rule for the temporary directory: root's with the
		// sticky bit, or the engine user's and writable by no one else.
		good := st != nil && ((st.Uid == 0 && fi.Mode()&os.ModeSticky != 0) ||
			(int(st.Uid) == os.Getuid() && fi.Mode().Perm()&otherWrite == 0))
		r.check("temp-dir-rule", good, fmt.Sprintf("%s mode %v", tmp, fi.Mode()))
	}
	sockDir, err := makeSocketDir(tmp)
	if err != nil {
		r.fail("socket-dir", err.Error())
		return
	}
	defer os.RemoveAll(sockDir)
	r.ok("socket-dir", "made "+sockDir+" mode 0700")
	tmpSock := filepath.Join(sockDir, "p.sock")
	stateSock := filepath.Join(filepath.Dir(copyDir), "run", "p.sock")

	cmd := exec.Command(filepath.Join(copyDir, "bin", "child"), "-child", "-state-socket", stateSock)
	cmd.Dir = copyDir
	cmd.Env = []string{socketEnv + "=" + tmpSock}
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		r.fail("exec-from-state-dir", err.Error())
		return
	}
	r.ok("exec-from-state-dir", fmt.Sprintf("started pid %d", cmd.Process.Pid))
	defer func() {
		// Stop the whole group, as the engine stops a plugin.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}()

	want := strconv.Itoa(os.Getuid())
	for _, s := range []struct{ name, path string }{
		{"reach-socket-in-temp-dir", tmpSock},
		{"reach-socket-in-state-dir", stateSock},
	} {
		got, err := ping(s.path)
		switch {
		case err != nil:
			r.fail(s.name, err.Error())
		case got != "pong "+want:
			r.fail(s.name, fmt.Sprintf("answered %q, want the engine's uid %s", got, want))
		default:
			r.ok(s.name, s.path+" answered "+got)
		}
	}
}

// sandboxEvidence shows the run is inside the unit's sandbox, so a pass is
// not only a run without one: on Linux no new privileges, a read-only
// system, a /tmp of its own; and it prints how the state directory is
// mounted.
func (r *report) sandboxEvidence(state, marker, readOnly string) {
	if runtime.GOOS != "linux" {
		r.ok("sandbox", runtime.GOOS+": no sandbox checks here")
		return
	}
	for _, key := range []string{"NoNewPrivs:", "Seccomp:", "CapEff:"} {
		v := procStatus(key)
		if key == "NoNewPrivs:" {
			r.check("no-new-privileges", v == "1", key+" "+v)
			continue
		}
		r.ok("status", key+" "+v)
	}
	if readOnly != "" {
		f, err := os.CreateTemp(readOnly, "spawn-")
		if err == nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			r.fail("control-read-only-system", "wrote in "+readOnly)
		} else {
			r.check("control-read-only-system", errors.Is(err, syscall.EROFS), err.Error())
		}
	}
	if marker != "" {
		_, err := os.Lstat(marker)
		r.check("control-private-tmp", errors.Is(err, os.ErrNotExist), fmt.Sprintf("host marker %s: %v", marker, err))
	}
	r.ok("state-dir-mount", mountOf(state))
}

func procStatus(key string) string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err.Error()
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, key); ok {
			return strings.TrimSpace(v)
		}
	}
	return "absent"
}

// mountOf names the mount that holds path and its options, from
// /proc/self/mountinfo: the longest mount point that is a prefix of path.
func mountOf(path string) string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err.Error()
	}
	best, opts := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		// Fields 5 and 6 (from 1) are the mount point and its options.
		f := strings.Fields(line)
		if len(f) <= mountOptsField {
			continue
		}
		mp := f[mountPointField]
		if (path == mp || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/")) && len(mp) >= len(best) {
			best, opts = mp, f[mountOptsField]
		}
	}
	return fmt.Sprintf("%s is on %s (%s)", path, best, opts)
}

func randomName(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// writeCopy writes this program's own bytes as <state>/spawn-<random>/copy/bin/child,
// as the engine writes a plugin copy it received, and returns the copy's
// directory.
func writeCopy(state string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	src, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer src.Close()
	name, err := randomName("spawn-")
	if err != nil {
		return "", err
	}
	copyDir := filepath.Join(state, name, "copy")
	if err := os.MkdirAll(filepath.Join(copyDir, "bin"), privateDir); err != nil {
		return "", err
	}
	dst, err := os.OpenFile(filepath.Join(copyDir, "bin", "child"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateDir)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return "", err
	}
	return copyDir, dst.Close()
}

// makeSocketDir makes a new mode-0700 directory in dir, as the engine makes a
// plugin's socket directory in same-user mode.
func makeSocketDir(dir string) (string, error) {
	name, err := randomName("basalt-plugin-")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, privateDir); err != nil {
		return "", err
	}
	return p, nil
}

// ping connects to path, retrying until the child listens, and returns its
// answer to "ping".
func ping(path string) (string, error) {
	deadline := time.Now().Add(reachWait)
	c, err := net.Dial("unix", path)
	for err != nil && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		c, err = net.Dial("unix", path)
	}
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(reachWait))
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line), err
}

// serveChild is the started program: it makes its own socket directory under
// the state directory, listens there and on the socket it was handed, and
// answers "pong <uid>" to each connection.
func serveChild(handed, stateSock string) int {
	if handed == "" || stateSock == "" {
		_, _ = fmt.Fprintln(os.Stderr, "spawn child: needs "+socketEnv+" and -state-socket")
		return 2
	}
	if err := os.Mkdir(filepath.Dir(stateSock), privateDir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "spawn FAIL child-socket-dir:", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stderr, "spawn ok child-socket-dir: made %s, working directory %s\n", filepath.Dir(stateSock), cwd())
	for _, p := range []string{handed, stateSock} {
		l, err := net.Listen("unix", p)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "spawn FAIL child-listen: %s: %v\n", p, err)
			return 1
		}
		go answer(l)
	}
	select {} // until the parent kills the group
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return err.Error()
	}
	return d
}

func answer(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
				_, _ = fmt.Fprintf(c, "pong %d\n", os.Getuid())
			}
		}()
	}
}
