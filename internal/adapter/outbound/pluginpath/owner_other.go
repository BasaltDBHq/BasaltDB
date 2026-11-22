//go:build !unix

package pluginpath

import (
	"errors"
	"io/fs"
	"os"
)

// errNoOwner: plugins are verified on Unix only, where file owners and mode
// bits are what the path rule checks. Elsewhere every check fails closed.
var errNoOwner = errors.New("plugins need a Unix system: file owners cannot be checked here")

func fileOwner(fs.FileInfo) (uint32, error) { return 0, errNoOwner }

func fileGroup(fs.FileInfo) uint32 { return 0 }

func CurrentUID() (uint32, error) { return 0, errNoOwner }

const NoFollowFlags = os.O_RDONLY
