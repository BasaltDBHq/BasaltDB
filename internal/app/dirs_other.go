//go:build !unix

package engine

// ensurePrivateDirs: the engine runs on Linux and macOS only.
func ensurePrivateDirs(int, ...string) error { return nil }
