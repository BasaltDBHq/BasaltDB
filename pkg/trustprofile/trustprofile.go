// Package trustprofile is the trust profiles that say which root
// certificates verify a database's certificate, beyond the system's
// authorities: one JSON file per provider or host, with the PEM files of its
// roots beside it. A profile names the hosts it applies to (match), the
// files of its roots, each pinned by the SHA-256 of its bytes, and
// optionally where the provider publishes each file (source).
//
// The built-in profiles (Supabase and Amazon RDS) are embedded in the
// binary; the engine adds the operator's own from trust.d next to its
// config. A matching profile's roots are added to the system's authorities
// for its hosts only, and only for connections that verify the host name
// (sslmode=verify-full). Each profile has its own pool, so one profile's
// roots never verify another profile's hosts (CONTRACT.md, Trust profiles).
//
// This package is the public Go API for other modules: its types are
// aliases and its functions forwards to the engine's own trust profile
// code, so both check a certificate the same way.
package trustprofile

import (
	"crypto/x509"
	"io/fs"

	core "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
	"github.com/basaltdbhq/basaltdb/internal/lib/certroots"
)

// Origin is where a profile comes from.
type Origin = core.Origin

// The origins of a profile.
const (
	// BuiltIn profiles are embedded in the binary.
	BuiltIn = core.BuiltIn
	// Operator profiles are files in trust.d next to the engine's config.
	Operator = core.Operator
)

// Verify values of a profile. VerifyFull checks the chain and the host
// name. VerifyCA, accepted only on a profile whose matches are all exact
// hosts (a pin), checks that the chain ends at one of the profile's own
// roots, not the system's, and does not check the name: for a server whose
// certificate does not name the host (an IP-only certificate).
const (
	VerifyFull = core.VerifyFull
	VerifyCA   = core.VerifyCA
)

// Limits on what a profile holds.
const (
	// MaxProfileBytes bounds a profile's JSON file.
	MaxProfileBytes = core.MaxProfileBytes
	// MaxRootFileBytes bounds one roots file; AWS's RDS bundle is about
	// 175 KB.
	MaxRootFileBytes = core.MaxRootFileBytes
)

// Spec is a profile's JSON file.
type Spec = core.Spec

// RootSpec is one roots file of a profile: its name next to the profile and
// the SHA-256 of its bytes.
type RootSpec = core.RootSpec

// Profile is a profile whose files were read and checked.
type Profile = core.Profile

// RootFile is one roots file, read and checked: its bytes match the pinned
// SHA-256 and hold only CA certificates.
type RootFile = core.RootFile

// Parse reads a profile's JSON and, through read, the roots files it names,
// and checks them: a valid name, at least one valid match entry and one
// roots file (unless disabled), each file's SHA-256 as pinned, and only CA
// certificates in them. A disabled profile is only an operator's and names
// nothing else. An operator profile's suffix entries must not be a public
// suffix on their own (CheckOperatorMatch). Any failure refuses the whole
// profile.
func Parse(raw []byte, origin Origin, read func(name string) ([]byte, error)) (*Profile, error) {
	return core.Parse(raw, origin, read, certroots.Store{})
}

// ParseCAs is every certificate in a PEM file, each a CA (basicConstraints
// CA:true): a file with no certificate, a block that is not a certificate,
// one that does not parse, one that is not a CA, or bytes after the last
// block is refused.
func ParseCAs(b []byte) ([]*x509.Certificate, error) { return core.ParseCAs(b) }

// ParseCerts is every certificate in a PEM file, CA or not, refused as
// ParseCAs refuses a file.
func ParseCerts(b []byte) ([]*x509.Certificate, error) { return core.ParseCerts(b) }

// FileSHA256 is the lowercase hex SHA-256 of b.
func FileSHA256(b []byte) string { return core.FileSHA256(b) }

// Fingerprint is the SHA-256 of a certificate's DER, uppercase hex in
// colon-separated pairs, as providers and browsers show it.
func Fingerprint(c *x509.Certificate) string { return core.Fingerprint(c) }

// NormalizeSHA256 is a SHA-256 in hex, any case, with or without colons,
// as lowercase hex without them.
func NormalizeSHA256(s string) (string, error) { return core.NormalizeSHA256(s) }

// ValidName reports whether s is a profile name: lowercase letters, digits
// and dashes, starting with a letter or digit, up to 63 characters.
func ValidName(s string) bool { return core.ValidName(s) }

// ValidFileName reports whether s is a plain file name a profile may name:
// no directory, not hidden, letters, digits, dots, dashes and underscores.
func ValidFileName(s string) bool { return core.ValidFileName(s) }

// NormalizeMatch is a match entry in lowercase without a trailing dot, or
// why it is not one: a DNS suffix (db.example.com matches its hosts below
// it), or =host, one exact host name or IP address.
func NormalizeMatch(entry string) (string, error) { return core.NormalizeMatch(entry) }

// NormalizeHost is a host as profiles compare it: lowercase, without a
// trailing dot.
func NormalizeHost(host string) string { return core.NormalizeHost(host) }

// PinName is the name of the pin profile for host: pin- and the host's
// letters and digits, the rest as dashes, up to the longest name. Two hosts
// can give one name; the pin's match says which host it is for.
func PinName(host string) string { return core.PinName(host) }

// DERSHA256 is the lowercase hex SHA-256 of a certificate's DER: the
// fingerprint pins, --trust-root and the ledger compare.
func DERSHA256(c *x509.Certificate) string { return core.DERSHA256(c) }

// ProviderName is the provider a built-in profile is for, as the confirm
// step names it ("Amazon RDS"); another profile's own name.
func ProviderName(profile string) string { return core.ProviderName(profile) }

// Refused is an operator file that was not loaded, and why.
type Refused = core.Refused

// State is how a profile of a Set stands.
type State = core.State

// The states of a listed profile.
const (
	// Active: the profile applies to its hosts.
	Active = core.Active
	// Replaced: a built-in profile an operator profile of the same name
	// replaces.
	Replaced = core.Replaced
	// Disabled: a built-in profile an operator profile turns off, or that
	// operator profile itself.
	Disabled = core.Disabled
)

// Listed is one profile of a Set with its state.
type Listed = core.Listed

// Set is the profiles that decide which roots verify a host: the built-in
// ones, the operator's, and the operator files that were refused. An
// operator profile with a built-in's name replaces it, or turns it off when
// disabled. A refused operator file named after a built-in (<name>.json)
// keeps that built-in off, since the file may have meant to disable or
// narrow it: a refusal never brings roots back.
type Set = core.Set

// NewSet is the set of builtin and operator profiles; refused are the
// operator files that were not loaded. Two profiles of one origin with the
// same name keep the first.
func NewSet(builtin, operator []*Profile, refused []Refused) *Set {
	return core.NewSet(builtin, operator, refused)
}

// BuiltIns are the embedded profiles, read once. The files are fixed at
// build time and pinned by tests, so one that does not load is a broken
// build.
var BuiltIns = core.LoadBuiltIns(certroots.Store{})

// BuiltInSet is the set of the built-in profiles alone.
var BuiltInSet = core.SetOf(BuiltIns)

// LoadFS loads every *.json profile in dir of fsys, its roots files read
// from the same directory, failing on the first that does not load.
func LoadFS(fsys fs.FS, dir string, origin Origin) ([]*Profile, error) {
	return core.LoadFS(fsys, dir, origin, certroots.Store{})
}

// FileName is the file a profile called name is kept in.
func FileName(name string) string { return core.FileName(name) }

// CheckFileName refuses a profile kept in a file not named after it, so two
// files can never hold one name.
func CheckFileName(file, name string) error { return core.CheckFileName(file, name) }

// FileError is a profile file that does not load.
type FileError = core.FileError

// PinFiles is a pin: the exact-host operator profile for one host that
// holds the one certificate a person accepted, and the files that hold it
// in trust.d.
type PinFiles = core.PinFiles

// NewPin is the pin for host holding cert (pin-<host>, match =host), with
// verify: ca when caOnly (a certificate that does not name the host). It is
// built in memory and written nowhere.
func NewPin(host string, cert *x509.Certificate, caOnly bool) (PinFiles, error) {
	return core.NewPin(host, cert, caOnly, certroots.Store{})
}

// CheckOperatorMatch refuses an operator's suffix entry that is a public
// suffix on its own, by Go's public suffix list (ICANN and private entries):
// a single label (com), a country's second level (co.uk, com.au), or a zone
// a provider hands out to many parties (github.io, cloudfront.net,
// s3.amazonaws.com, elb.amazonaws.com). It also refuses a short list of
// shared cloud and database zones the list does not mark (amazonaws.com,
// rds.amazonaws.com, database.windows.net). A profile for one of them would
// be a global root by another name. A domain below a public suffix
// (db.example.com) and an exact host (=host) are never refused here.
func CheckOperatorMatch(m string) error { return core.CheckOperatorMatch(m) }

// VerifyFullByDefault is dsn with sslmode=verify-full when it names no
// sslmode and its one host is one a built-in profile of set covers
// (Supabase, Amazon RDS): the provider's roots are known, so the
// certificate is checked without the person asking for it. The parameter
// is appended and the rest of the string kept byte for byte. Anything
// else is returned as given: an explicit sslmode (whatever its value), a
// string that names its own root (sslrootcert), a host no profile covers or
// one an operator's profile decides for (a pin, a replaced or disabled
// built-in), several hosts, a host parameter, a fragment, a key=value
// string or one that does not parse.
func VerifyFullByDefault(dsn string, set *Set) string { return core.VerifyFullByDefault(dsn, set) }

// BuiltInProvider is the provider whose built-in profile of set is the one
// that applies to host ("Supabase", "Amazon RDS"), "" when none does (no
// profile covers it, or an operator's profile decides for it).
func BuiltInProvider(host string, set *Set) string { return core.BuiltInProvider(host, set) }

// ErrPublic is a pin, or a verify: ca root, of a publicly trusted
// certificate authority.
var ErrPublic = core.ErrPublic

// SetSystemRootsForTest makes pool the system's trust store for IsPublic
// with a nil pool, Parse and package trustpin, until restore is called.
// Only tests call it.
func SetSystemRootsForTest(pool *x509.CertPool) (restore func()) {
	return certroots.SetSystemRootsForTest(pool)
}

// SystemRoots is the system's trust store.
func SystemRoots() (*x509.CertPool, error) { return certroots.SystemRoots() }

// PublicRoots are the publicly trusted roots this binary carries: the
// Mozilla (NSS) root store, whatever the system's store holds. They are
// verified with Go's own verifier, so the answer is the same on every
// system. A root NSS constrains (a distrust date) counts as public all the
// same: refusing more is safe.
var PublicRoots = certroots.PublicRoots

// IsPublic reports whether c is, or chains to, a publicly trusted root:
// one of PublicRoots, or a root of system (the system's trust store when
// nil, which also holds the roots an administrator added).
func IsPublic(c *x509.Certificate, system *x509.CertPool) bool {
	return core.IsPublic(c, system, certroots.Store{})
}
