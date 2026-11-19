// Command probe is the plugin scripts/systemd-smoke/smoke.sh installs as a
// service unit on a host with systemd (make test-systemd). Before it serves,
// it tries what its unit must take away and writes one line per check to
// stderr, which the journal keeps under the unit:
//
//	probe ok <check>: <what it saw>
//	probe FAIL <check>: <what it saw>
//	probe done
//
// Then it serves like any plugin built with the SDK; initialize writes
// "probe initialized", so the smoke test sees that the engine connected.
//
// With -control it runs the same checks outside the unit (the smoke test runs
// it as the plugin's OS user), expects none of the unit's effects, and exits.
// That shows each check sees the unit's sandbox, not a file mode or the OS
// user alone.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/plugin/sdk"
)

// The name and version must equal the manifest the smoke test writes.
const (
	pluginName    = "sandbox-probe"
	pluginVersion = "0.1.0"
)

// ownerOnly is the mode the chmod check sets on its own file.
const ownerOnly = 0o600

type probe struct{ out io.Writer }

func (probe) Info() sdk.Info { return sdk.Info{Name: pluginName, Version: pluginVersion} }

// ObserveFeed makes the probe a feed observer, the hook its manifest
// declares. It notes each batch and handles every event.
func (p probe) ObserveFeed(_ context.Context, b sdk.FeedBatch) (int64, error) {
	if _, err := fmt.Fprintf(p.out, "probe feed: %d events\n", len(b.Events)); err != nil {
		return 0, err
	}
	return b.LastSeq(), nil
}

func (p probe) Initialize(context.Context, sdk.Init) error {
	_, err := fmt.Fprintln(p.out, "probe initialized")
	return err
}

// check is one thing the unit takes away. seen runs it and reports whether
// the unit's effect showed, with what it saw.
type check struct {
	name string
	seen func() (bool, string)
}

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet(pluginName, flag.ContinueOnError)
	control := fs.Bool("control", false, "run the checks outside the unit, expect none of its effects, and exit")
	hidden := fs.String("hidden", "", "comma-separated paths the unit makes inaccessible")
	marker := fs.String("marker", "", "a file the smoke test made in the host's /tmp")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	socket := os.Getenv(sdk.SocketEnv)
	if socket == "" || *hidden == "" || *marker == "" {
		_, _ = fmt.Fprintln(out, "probe: needs -hidden, -marker and "+sdk.SocketEnv)
		return 2
	}

	failed := 0
	for _, c := range checks(strings.Split(*hidden, ","), *marker) {
		seen, what := c.seen()
		if seen == *control {
			failed++
			_, _ = fmt.Fprintf(out, "probe FAIL %s: %s\n", c.name, what)
			continue
		}
		_, _ = fmt.Fprintf(out, "probe ok %s: %s\n", c.name, what)
	}
	_, _ = fmt.Fprintln(out, "probe done")
	if *control {
		if failed > 0 {
			return 1
		}
		return 0
	}

	// A failed check is the smoke test's to report: the plugin still serves,
	// so the engine's side is checked as well.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Serve(ctx, probe{out: out})
	if err != nil {
		_, _ = fmt.Fprintln(out, "probe:", err)
		return 1
	}
	return 0
}

func checks(hidden []string, marker string) []check {
	fixed := []check{
		{"no-inet-socket", noSocket(syscall.AF_INET)},
		{"no-inet6-socket", noSocket(syscall.AF_INET6)},
		{"no-chmod", noChmod},
		{"read-only-copy", readOnlyCopy},
		{"private-tmp", privateTmp(marker)},
		{"home-hidden", inaccessible("/home")},
		{"other-processes-hidden", otherProcessesHidden},
		{"no-new-privileges", procStatus("NoNewPrivs:", "1")},
		{"no-bounding-capabilities", procStatus("CapBnd:", "0000000000000000")},
	}
	cs := make([]check, 0, len(fixed)+len(hidden))
	cs = append(cs, fixed...)
	for _, p := range hidden {
		cs = append(cs, check{"hidden " + p, inaccessible(p)})
	}
	return cs
}

// noSocket: with an empty egress the unit allows Unix sockets only
// (RestrictAddressFamilies=AF_UNIX).
func noSocket(family int) func() (bool, string) {
	return func() (bool, string) {
		fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
		if err == nil {
			_ = syscall.Close(fd)
			return false, "socket opened"
		}
		return errors.Is(err, syscall.EAFNOSUPPORT), err.Error()
	}
}

// noChmod: the unit's system call filter refuses every chmod call, so the
// plugin cannot open its socket directory or socket to others. It tries on a
// file of its own in /tmp: chmod on the socket directory outside the unit
// would drop the directory's setgid bit, since the plugin's user is not in
// its group.
func noChmod() (bool, string) {
	f, err := os.CreateTemp("", "probe-")
	if err != nil {
		return false, err.Error()
	}
	_ = f.Close()
	defer os.Remove(f.Name())
	err = os.Chmod(f.Name(), ownerOnly)
	if err == nil {
		return false, "chmod worked"
	}
	return errors.Is(err, syscall.EPERM), err.Error()
}

// readOnlyCopy: ProtectSystem=strict mounts the installed copy (the working
// directory) read-only. Outside the unit the copy is root's, so writing fails
// with a permission error instead.
func readOnlyCopy() (bool, string) {
	f, err := os.CreateTemp(".", "probe-")
	if err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return false, "wrote in the installed copy"
	}
	return errors.Is(err, syscall.EROFS), err.Error()
}

// privateTmp: the unit has a /tmp of its own, without the host's marker.
func privateTmp(marker string) func() (bool, string) {
	return func() (bool, string) {
		_, err := os.Lstat(marker)
		if err == nil {
			return false, "sees " + marker
		}
		return errors.Is(err, os.ErrNotExist), err.Error()
	}
}

// inaccessible: InaccessiblePaths and ProtectHome put a mode-0000 node over
// the path, so even its directory entry cannot be read. Outside the unit the
// path has its own mode.
func inaccessible(path string) func() (bool, string) {
	return func() (bool, string) {
		fi, err := os.Stat(path)
		if err != nil {
			return false, err.Error()
		}
		if fi.Mode().Perm() != 0 {
			return false, fmt.Sprintf("mode %v", fi.Mode())
		}
		_, err = os.ReadDir(path)
		if err == nil && fi.IsDir() {
			return false, "mode 0000, but listed"
		}
		return true, "mode 0000"
	}
}

// otherProcessesHidden: ProtectProc=invisible hides processes of other
// users, so PID 1 (root's) is not in /proc.
func otherProcessesHidden() (bool, string) {
	_, err := os.Stat("/proc/1")
	if err == nil {
		return false, "/proc/1 is visible"
	}
	return errors.Is(err, os.ErrNotExist), err.Error()
}

// procStatus: a line of /proc/self/status has the value the unit sets.
func procStatus(key, want string) func() (bool, string) {
	return func() (bool, string) {
		b, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return false, err.Error()
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, key); ok {
				v = strings.TrimSpace(v)
				return v == want, key + " " + v
			}
		}
		return false, "no " + key + " line"
	}
}
