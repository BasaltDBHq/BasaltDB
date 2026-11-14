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

// LockOpenFile: see lock_unix.go.
func LockOpenFile(*os.File) (func(), error) { return nil, errNoLock }

// ReadOwnCredential: see lock_unix.go.
func ReadOwnCredential(string) (string, os.FileInfo, error) { return "", nil, errNoLock }

// SameCredentialFile: see lock_unix.go.
func SameCredentialFile(string, os.FileInfo) error { return errNoLock }
