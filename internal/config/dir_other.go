//go:build !unix

package config

import "os"

// waitLock: see lock_unix.go.
func waitLock(lock func() (func(), error)) (func(), error) { return lock() }

// LockAt: see dir_unix.go.
func LockAt(Dir, string) (func(), error) { return nil, errNoLock }

// OpenPlainAt: see dir_unix.go.
func OpenPlainAt(Dir, string, func(*os.File) error) (*os.File, error) { return nil, errNoLock }

// CheckTrustedConfig: see dir_unix.go.
func CheckTrustedConfig(*os.File, int) error { return errNoLock }

// ReadCredentialAt: see dir_unix.go.
func ReadCredentialAt(Dir, string) (string, os.FileInfo, error) { return "", nil, errNoLock }

// ReadCredentialAtLimit: see dir_unix.go.
func ReadCredentialAtLimit(Dir, string, int) (string, os.FileInfo, error) { return "", nil, errNoLock }

// SameFileAt: see dir_unix.go.
func SameFileAt(Dir, string, os.FileInfo) error { return errNoLock }
