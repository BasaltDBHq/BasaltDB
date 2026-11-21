// Package binwatch notices a new basalt binary installed over the one the
// engine runs, so the engine can restart onto it with no service manager
// (CONTRACT.md, Next steps, Engine restarts). It watches the path the
// engine was started from, not the file it resolved to, so a package
// manager that points a symlink at a new version is seen too.
package binwatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"
)

// DefaultInterval is how often the binary's path is looked at. A new file
// is used once it was seen unchanged twice in a row, so one still being
// copied is never run.
const DefaultInterval = 5 * time.Second

// Identity is what tells one file at a path from another: a new file
// (rename over, new symlink target) changes the inode, a copy over the old
// one changes its size or modification time.
type Identity struct {
	Dev, Ino uint64
	Size     int64
	ModNanos int64
	Mode     uint32
}

// System is what the watcher needs from the machine. OS is the real one.
type System interface {
	// Stat is the identity of the file at path, following symlinks.
	Stat(path string) (Identity, error)
	// Trusted refuses a binary anyone but root could change (the check
	// basalt service install makes).
	Trusted(path string) error
	// Probe runs the binary at path (basalt version) and returns its
	// version; an error when it does not run or is not basalt.
	Probe(ctx context.Context, path string) (string, error)
}

// Watcher waits for a new binary at Path.
type Watcher struct {
	path     string
	sys      System
	interval time.Duration
	// trusted is set when the binary the engine started from passed the
	// root-only check, or the engine runs as root: a new one must pass it
	// too, so a restart never runs a binary that is less protected.
	trusted bool
	log     *slog.Logger
	base    Identity
}

// New watches path from now on: its current file is the one the engine
// runs. exe is the running binary's own path (os.Executable): whether it
// is protected decides whether every new binary must be. When it is and
// path is not (a symlink or a hard link in a directory others can change),
// exe is watched instead, so a restart never goes through a less protected
// path. A path that cannot be read is an error, and the engine then runs
// without the restart.
func New(path, exe string, sys System, asRoot bool, log *slog.Logger) (*Watcher, error) {
	if sys == nil || log == nil {
		panic("binwatch: system and logger required")
	}
	if !filepath.IsAbs(path) || !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("binary paths %q and %q must be absolute", path, exe)
	}
	trusted := asRoot || sys.Trusted(exe) == nil
	if trusted && sys.Trusted(path) != nil {
		path = exe
	}
	base, err := sys.Stat(path)
	if err != nil {
		return nil, err
	}
	return &Watcher{path: path, sys: sys, interval: DefaultInterval, trusted: trusted, log: log, base: base}, nil
}

// Recheck runs the protection check once more on the path, right before
// the restart runs it; nil when no check applies.
func (w *Watcher) Recheck() error {
	if !w.trusted {
		return nil
	}
	return w.sys.Trusted(w.path)
}

// WithInterval sets how often the path is looked at (tests).
func (w *Watcher) WithInterval(d time.Duration) *Watcher {
	w.interval = d
	return w
}

// Path is the binary path the engine restarts onto.
func (w *Watcher) Path() string { return w.path }

// Wait blocks until a new binary at the path is in place: seen unchanged
// on two looks in a row, as protected as the one the engine started from
// and answering basalt version. It returns nil then, and the file becomes
// the one Wait compares with next time (so a restart that fails is not
// tried again until the binary changes again). It returns ctx's error when
// ctx ends first. A new binary that fails a check is logged once and
// skipped until it changes again.
func (w *Watcher) Wait(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	var seen *Identity
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		id, err := w.sys.Stat(w.path)
		switch {
		case err != nil, id == w.base:
			// Missing for a moment (an installer between remove and
			// rename), or still the running binary.
			seen = nil
			continue
		case seen == nil || *seen != id:
			seen = &id
			continue
		}
		seen = nil
		w.base = id
		version, err := w.check(ctx)
		if err != nil {
			w.log.Warn("a new basalt binary is installed but the engine does not restart onto it", "path", w.path, "err", err)
			continue
		}
		w.log.Info("a new basalt binary is installed", "path", w.path, "version", version)
		return nil
	}
}

// probeTimeout bounds basalt version on the new binary.
const probeTimeout = 10 * time.Second

func (w *Watcher) check(ctx context.Context) (string, error) {
	if err := w.Recheck(); err != nil {
		return "", err
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	version, err := w.sys.Probe(pctx, w.path)
	if err != nil {
		return "", fmt.Errorf("basalt version on the new binary: %w", err)
	}
	return version, nil
}

// errNotBasalt is a probed binary whose version line is not basalt's.
var errNotBasalt = errors.New("it does not print a basalt version")

// parseVersion reads basalt version's output: "basalt <version>".
func parseVersion(out string) (string, error) {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	v, ok := strings.CutPrefix(line, "basalt ")
	if !ok || strings.TrimSpace(v) == "" {
		return "", errNotBasalt
	}
	return strings.TrimSpace(v), nil
}

// ExecPath is the path the engine restarts onto: the path it was started
// with (argv[0], found on PATH when it has no slash), so a symlink that now
// points at a newer version is followed. When that path does not lead to
// the running binary (argv[0] can be anything), it is the running binary's
// own path, from executable.
func ExecPath(arg0 string, lookPath func(string) (string, error), executable func() (string, error), stat func(string) (Identity, error)) (string, error) {
	exe, err := executable()
	if err != nil {
		return "", err
	}
	p := arg0
	if !strings.Contains(arg0, "/") {
		if p, err = lookPath(arg0); err != nil {
			return exe, nil
		}
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return exe, nil //nolint:nilerr // argv[0] is unusable: the running binary's own path
	}
	got, err := stat(p)
	if err != nil {
		return exe, nil //nolint:nilerr // argv[0] is unusable: the running binary's own path
	}
	want, err := stat(exe)
	if err != nil || got.Dev != want.Dev || got.Ino != want.Ino {
		return exe, nil //nolint:nilerr // argv[0] is another file: the running binary's own path
	}
	return p, nil
}
