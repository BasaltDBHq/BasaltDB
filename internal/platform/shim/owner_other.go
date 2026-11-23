//go:build !unix

package shim

import "os"

// ownedByMe has no owner to check outside unix; the directory's mode and
// the user cache dir it lives in stand in for it.
func ownedByMe(os.FileInfo) bool { return true }
