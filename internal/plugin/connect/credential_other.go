//go:build !unix

package connect

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// checkCredentialFileInfo has no owner or mode bits to check here: the
// owner and 0600 rule is enforced on Unix only, as for the engine's key files.
func checkCredentialFileInfo(os.FileInfo) string { return "" }
