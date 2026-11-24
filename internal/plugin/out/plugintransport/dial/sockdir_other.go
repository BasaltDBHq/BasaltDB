//go:build !unix

package dial

import "errors"

// SocketDirIs: without Unix owners no socket directory passes.
func SocketDirIs(string, uint32, uint32) bool { return false }

// makeSocketDir: socket plugins need a Unix system.
func makeSocketDir(string, string) error {
	return errors.New("plugin socket directories need a Unix system")
}

// openedByACL: without Unix sockets no socket passes.
func openedByACL(string) bool { return true }
