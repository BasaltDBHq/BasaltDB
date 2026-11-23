package app

import (
	"errors"
	"io/fs"
)

// errNotExist reports whether err is a missing file.
func errNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
