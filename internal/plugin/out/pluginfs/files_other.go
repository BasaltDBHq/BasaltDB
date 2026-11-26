//go:build !unix

package pluginfs

import "io/fs"

// NoFollow: no flag refuses a symlink here.
func (Files) NoFollow() int { return 0 }

// Owner: no file carries an owner here.
func (Files) Owner(fs.FileInfo) (uint32, bool) { return 0, false }

// Links: no file carries a link count here.
func (Files) Links(fs.FileInfo) (uint64, bool) { return 0, false }
