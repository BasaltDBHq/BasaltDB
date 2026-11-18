//go:build !unix

package plugin

import (
	"errors"
	"io/fs"
	"os"
)

// errNoOwner: plugins are verified on Unix only, where file owners and mode
// bits are what the path rule checks. Elsewhere every check fails closed.
var errNoOwner = errors.New("plugins need a Unix system: file owners cannot be checked here")

func fileOwner(fs.FileInfo) (uint32, error) { return 0, errNoOwner }

func currentUID() (uint32, error) { return 0, errNoOwner }

const noFollowFlags = os.O_RDONLY
