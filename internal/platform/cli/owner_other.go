//go:build !unix

package cli

import "os"

// InfoOwnerUID has no owner to read off unix.
func InfoOwnerUID(os.FileInfo) (int, bool) { return 0, false }
