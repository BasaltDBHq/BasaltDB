package trustprofile

import core "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"

// Profiles are every profile of the set, operator ones first, each with its
// state.
func Profiles(s *Set) []Listed { return core.Profiles(s) }

// BuiltInNamed is the built-in profile called name, or nil.
func BuiltInNamed(name string) *Profile {
	for _, p := range BuiltIns() {
		if p.Name == name {
			return p
		}
	}
	return nil
}
