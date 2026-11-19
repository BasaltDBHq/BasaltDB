//go:build !unix

package dial

// SocketDirIs: without Unix owners no socket directory passes.
func SocketDirIs(string, uint32, uint32) bool { return false }
