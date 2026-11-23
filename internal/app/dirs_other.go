//go:build !unix

package app

// ensurePrivateDirs: the engine runs on Linux and macOS only.
func ensurePrivateDirs(int, ...string) error { return nil }
