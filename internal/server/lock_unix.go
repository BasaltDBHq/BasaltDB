//go:build unix

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Lock is an exclusive flock on the pidfile, held for the server's lifetime.
// The kernel drops it when the process exits, so a crashed server never
// leaves a stale lock; the file itself is kept to avoid unlink races.
type Lock struct {
	f *os.File
}

const lockFilePerm = 0o644

// AcquireLock takes the pidfile lock or returns *AlreadyRunningError.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), dataDirPermMode); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, lockFilePerm)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			pid, _ := readPID(path)
			return nil, &AlreadyRunningError{PID: pid, PIDFile: path}
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

func (l *Lock) WritePID(pid int) error {
	if err := l.f.Truncate(0); err != nil {
		return err
	}
	if _, err := l.f.WriteAt([]byte(strconv.Itoa(pid)+"\n"), 0); err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Lock) Release() {
	// Best effort: closing the file releases the lock anyway.
	_ = l.f.Truncate(0)
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
}

// Running reports whether a server holds the pidfile lock, and its pid.
func Running(path string) (pid int, running bool, err error) {
	l, err := AcquireLock(path)
	var already *AlreadyRunningError
	if errors.As(err, &already) {
		if already.PID > 0 {
			return already.PID, true, nil
		}
		// Lock is held but the pid has not been written yet (or is unreadable).
		if n, readErr := readPID(path); readErr == nil && n > 0 {
			return n, true, nil
		}
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	// Probe only: drop the lock without truncating the pidfile (Release does).
	l.f.Close()
	return 0, false, nil
}

func readPID(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
