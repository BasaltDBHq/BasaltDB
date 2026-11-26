//go:build !unix

package atomicfile

// SyncDir is a no-op outside Unix: a directory cannot be opened for sync.
func SyncDir(string) error { return nil }
