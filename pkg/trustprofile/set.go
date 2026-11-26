package trustprofile

import (
	"cmp"
	"embed"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Refused is an operator file that was not loaded, and why.
type Refused struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// State is how a profile of a Set stands.
type State string

// The states of a listed profile.
const (
	// Active: the profile applies to its hosts.
	Active State = "ACTIVE"
	// Replaced: a built-in profile an operator profile of the same name
	// replaces.
	Replaced State = "REPLACED"
	// Disabled: a built-in profile an operator profile turns off, or that
	// operator profile itself.
	Disabled State = "DISABLED"
)

// Listed is one profile of a Set with its state.
type Listed struct {
	*Profile
	State State
}

// Set is the profiles that decide which roots verify a host: the built-in
// ones, the operator's, and the operator files that were refused. An
// operator profile with a built-in's name replaces it, or turns it off when
// disabled. A refused operator file named after a built-in (<name>.json)
// keeps that built-in off, since the file may have meant to disable or
// narrow it: a refusal never brings roots back.
type Set struct {
	operator, builtin []*Profile
	listed            []Listed
	refused           []Refused
}

// NewSet is the set of builtin and operator profiles; refused are the
// operator files that were not loaded. Two profiles of one origin with the
// same name keep the first.
func NewSet(builtin, operator []*Profile, refused []Refused) *Set {
	s := &Set{refused: slices.Clone(refused)}
	off := map[string]bool{}
	for _, r := range refused {
		off[strings.TrimSuffix(filepath.Base(r.File), jsonExt)] = true
	}
	ops := map[string]*Profile{}
	for _, p := range uniqueByName(operator) {
		ops[p.Name] = p
		if p.Disabled {
			s.listed = append(s.listed, Listed{Profile: p, State: Disabled})
			continue
		}
		s.operator = append(s.operator, p)
		s.listed = append(s.listed, Listed{Profile: p, State: Active})
	}
	for _, p := range uniqueByName(builtin) {
		op, over := ops[p.Name]
		switch {
		case off[p.Name] && !over:
			s.listed = append(s.listed, Listed{Profile: p, State: Disabled})
		case over && op.Disabled:
			s.listed = append(s.listed, Listed{Profile: p, State: Disabled})
		case over:
			s.listed = append(s.listed, Listed{Profile: p, State: Replaced})
		default:
			s.builtin = append(s.builtin, p)
			s.listed = append(s.listed, Listed{Profile: p, State: Active})
		}
	}
	return s
}

func uniqueByName(ps []*Profile) []*Profile {
	out := make([]*Profile, 0, len(ps))
	seen := map[string]bool{}
	for _, p := range ps {
		if p == nil || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	slices.SortStableFunc(out, func(a, b *Profile) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// For is the profile whose roots verify host, or nil for the system's
// authorities alone. First match wins: an exact host (=host), the
// operator's profiles before the built-in ones; then the operator's suffix
// profiles, longest suffix first; then the built-in suffix profiles,
// longest suffix first. Ties go to the profile name that sorts first.
func (s *Set) For(host string) *Profile {
	if s == nil {
		return nil
	}
	h := NormalizeHost(host)
	if h == "" || strings.HasPrefix(h, "/") {
		return nil
	}
	for _, exact := range []bool{true, false} {
		for _, group := range [][]*Profile{s.operator, s.builtin} {
			if p := longest(group, h, exact); p != nil {
				return p
			}
		}
	}
	return nil
}

func longest(group []*Profile, host string, exact bool) *Profile {
	var best *Profile
	bestLen := 0
	for _, p := range group {
		if n := p.matchLen(host, exact); n > bestLen {
			best, bestLen = p, n
		}
	}
	return best
}

// Refused are the operator files that were not loaded.
func (s *Set) Refused() []Refused { return slices.Clone(s.refused) }

//go:embed profiles
var builtinFS embed.FS

// builtinDir is the embedded directory of the built-in profiles.
const builtinDir = "profiles"

// BuiltIns are the embedded profiles, read once. The files are fixed at
// build time and pinned by tests, so one that does not load is a broken
// build.
var BuiltIns = sync.OnceValue(func() []*Profile {
	ps, err := LoadFS(builtinFS, builtinDir, BuiltIn)
	if err != nil {
		panic("trustprofile: a built-in profile does not load: " + err.Error())
	}
	return ps
})

// BuiltInSet is the set of the built-in profiles alone.
var BuiltInSet = sync.OnceValue(func() *Set { return NewSet(BuiltIns(), nil, nil) })

// LoadFS loads every *.json profile in dir of fsys, its roots files read
// from the same directory, failing on the first that does not load.
func LoadFS(fsys fs.FS, dir string, origin Origin) ([]*Profile, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []*Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), jsonExt) {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		p, err := Parse(raw, origin, func(name string) ([]byte, error) { return fs.ReadFile(fsys, path.Join(dir, name)) })
		if err != nil {
			return nil, &FileError{File: e.Name(), Err: err}
		}
		if err := CheckFileName(e.Name(), p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// jsonExt is the extension of a profile file.
const jsonExt = ".json"

// FileName is the file a profile called name is kept in.
func FileName(name string) string { return name + jsonExt }

// CheckFileName refuses a profile kept in a file not named after it, so two
// files can never hold one name.
func CheckFileName(file, name string) error {
	if file != FileName(name) {
		return &FileError{File: file, Err: nameMismatchError(name)}
	}
	return nil
}

// nameMismatchError is a profile named other than its file.
type nameMismatchError string

func (e nameMismatchError) Error() string {
	return "the profile is named " + string(e) + ", so its file must be " + FileName(string(e))
}

// FileError is a profile file that does not load.
type FileError struct {
	File string
	Err  error
}

func (e *FileError) Error() string { return e.File + ": " + e.Err.Error() }

func (e *FileError) Unwrap() error { return e.Err }

// Replacing is s with the operator profile name left out and add, when not
// nil, in its place: a pin that applies before it is written, or a pin
// left out.
func (s *Set) Replacing(name string, add *Profile) *Set {
	var ops, builtin []*Profile
	for _, l := range s.listed {
		switch {
		case l.Origin == Operator && l.Name == name:
		case l.Origin == Operator:
			ops = append(ops, l.Profile)
		default:
			builtin = append(builtin, l.Profile)
		}
	}
	if add != nil {
		ops = append(ops, add)
	}
	return NewSet(builtin, ops, s.refused)
}
