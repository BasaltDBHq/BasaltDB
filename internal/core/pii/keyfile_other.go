//go:build !unix

package pii

import "os"

// openNoFollow opens path read-only. Outside Unix there is no O_NOFOLLOW; the
// Lstat and SameFile checks in readMaster still refuse a link.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// checkOwner is a no-op outside Unix: ownership is an ACL there, and the
// engine's state directory is protected by the service install.
func checkOwner(os.FileInfo) error { return nil }

// syncDir is a no-op outside Unix, where a directory cannot be opened for sync.
func syncDir(string) error { return nil }
