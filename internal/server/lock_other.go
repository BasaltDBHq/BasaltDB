//go:build !unix

package server

import (
	"os"
	"strconv"
)

// Lock only records the pid on platforms without flock; it does not prevent
// a second server from starting.
type Lock struct{ path string }

func AcquireLock(path string) (*Lock, error) { return &Lock{path: path}, nil }

func (l *Lock) WritePID(pid int) error {
	return os.WriteFile(l.path, []byte(strconv.Itoa(pid)+"\n"), 0o644)
}

func (l *Lock) Release() { os.Remove(l.path) }

func Running(path string) (int, bool, error) { return 0, false, nil }
