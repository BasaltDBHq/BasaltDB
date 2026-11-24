//go:build !unix

package atomicfile

// syncDir is a no-op outside Unix: a directory cannot be opened for sync.
func syncDir(string) error { return nil }
