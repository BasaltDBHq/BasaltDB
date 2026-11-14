//go:build !unix

package config

import (
	"errors"
	"os"
)

// ErrLocked: see lock_unix.go.
var ErrLocked = errors.New("locked")

var errNoLock = errors.New("agent locks and credential promotion run on linux and darwin only")

// lockConfig: the engine and basalt init --remote run on linux and darwin
// only, so nothing else writes the config here.
func lockConfig(string) (func(), error) { return func() {}, nil }

// LockFile: see lock_unix.go.
func LockFile(string) (func(), error) { return nil, errNoLock }

// HeldLock: see lock_unix.go.
type HeldLock struct{}

// Release: see lock_unix.go.
func (HeldLock) Release() {}

// HandTo: see lock_unix.go.
func (HeldLock) HandTo(int) error { return nil }

// LockConfigAs: see lock_unix.go.
func LockConfigAs(string, int) (HeldLock, error) { return HeldLock{}, nil }

// LockUnusableError: see lock_unix.go.
type LockUnusableError struct {
	Path string
	Err  error
}

func (e *LockUnusableError) Error() string { return "lock " + e.Path + ": " + e.Err.Error() }

func (e *LockUnusableError) Unwrap() error { return e.Err }

// ReadOwnCredential: see lock_unix.go.
func ReadOwnCredential(string) (string, os.FileInfo, error) { return "", nil, errNoLock }

// SameCredentialFile: see lock_unix.go.
func SameCredentialFile(string, os.FileInfo) error { return errNoLock }
