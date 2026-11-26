//go:build !unix

package engineos

import "os"

// MakePrivateDirs: the engine runs on Linux and macOS only.
func (OS) MakePrivateDirs(int, os.FileMode, ...string) error { return nil }
