// Package trustdir is the operator's trust profiles: the files in trust.d,
// the directory next to the engine's config (CONTRACT.md, Trust profiles).
// They are read with the rules the engine applies to engine.json and the
// credential file: the directory and every file owned by root or the
// config directory's owner (the engine's OS user), not writable by group or
// others, reached without following a link anyone but root controls, each
// file a regular file with one link. A file that breaks a rule, or a
// profile that does not load, is refused and named; it changes nothing.
package trustdir

import (
	"errors"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// DirName is the operator's profile directory, next to engine.json.
const DirName = "trust.d"

// ErrExists: trust.d already holds a profile of that name.
var ErrExists = errors.New("trust.d already holds a profile of that name")

// ErrNotFound: trust.d holds no profile of that name.
var ErrNotFound = errors.New("trust.d holds no profile of that name")

// maxProfiles bounds the profiles read from trust.d.
const maxProfiles = 64

// Path is the trust.d of the config at configPath.
func Path(configPath string) string { return filepath.Join(filepath.Dir(configPath), DirName) }

// Set is the built-in profiles with the operator's from configPath's
// trust.d, read now.
func Set(configPath string) *trustprofile.Set {
	ops, refused := Load(configPath)
	return trustprofile.NewSet(trustprofile.BuiltIns(), ops, refused)
}

// Source is Set for configPath as a source pgdial.SetTrust reads on each
// connection.
func Source(configPath string) func() *trustprofile.Set {
	return func() *trustprofile.Set { return Set(configPath) }
}
