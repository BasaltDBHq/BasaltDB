//go:build !unix

package connect

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// checkCredentialFileInfo has no owner or mode bits to check here.
func checkCredentialFileInfo(os.FileInfo) string { return "" }
