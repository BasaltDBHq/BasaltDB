package pluginmodel

import "io/fs"

// Refusal is why a plugin was refused: the reason of the PLUGIN_REFUSED
// error at basalt plugin add. At engine start every refusal shows in status
// as PLUGIN_NOT_TRUSTED.
type Refusal string

// The refusals verification gives.
const (
	// RefusedBadManifest: the manifest breaks a rule of CONTRACT.md, Plugins,
	// Manifest.
	RefusedBadManifest Refusal = "BAD_MANIFEST"
	// RefusedNotTrusted: the signature, a file's hash, the copy's contents or
	// a path's owner or permissions failed.
	RefusedNotTrusted Refusal = "NOT_TRUSTED"
)

// VerifyError is a refused plugin. It names the file or directory and the
// rule that failed, never a file's contents, a value from the manifest or
// key material.
type VerifyError struct {
	Reason Refusal
	// File is the path the check failed on: the manifest, its signature, an
	// installed file, a directory, or a key in the trust store.
	File string
	// Why is the rule that failed, in fixed words.
	Why string
	// Path is set when the path rule refused File for who can write it, a
	// symlink or its owner: something on the machine to fix, which no
	// trusted key changes. It is nil for every other refusal.
	Path *PathFault
}

// PathFaultKind is which part of the path rule a path failed.
type PathFaultKind string

// The path rule's parts a refusal names.
const (
	// PathWritable: someone besides the owner can write the path.
	PathWritable PathFaultKind = "WRITABLE"
	// PathSymlink: the path is a symlink the rule does not follow.
	PathSymlink PathFaultKind = "SYMLINK"
	// PathOwner: the path is owned by a user the rule does not allow there.
	PathOwner PathFaultKind = "OWNER"
)

// PathFault is what the path rule found at a refused path, read from the
// path itself (not followed if it is a symlink).
type PathFault struct {
	Kind PathFaultKind
	// UID and GID own the path; Mode is its mode.
	UID, GID uint32
	Mode     fs.FileMode
	// Owners are the users allowed to own it there: root and the required
	// owner above a root, the required owner from a root down, root for a
	// symlink above a root.
	Owners []uint32
}

// Error implements error.
func (e *VerifyError) Error() string {
	return "plugin " + e.File + ": " + e.Why + " (" + string(e.Reason) + ")"
}

// Verified is a plugin copy that passed every check.
type Verified struct {
	// Manifest is the copy's manifest.
	Manifest Manifest
	// ManifestSHA256 is the SHA-256 of the manifest's exact bytes, lowercase
	// hex: the entry's manifestSha256 and the copy's directory name.
	ManifestSHA256 string
	// Signer is who vouches for the copy: KNOWN when a built-in publisher
	// key signed the manifest, UNKNOWN otherwise.
	Signer SignerState
	// SignerKeyID is the id of the key that signed the manifest: a trusted
	// key's without RequireApproval, and with it only a KNOWN signer's,
	// empty otherwise.
	SignerKeyID string
	// Dir is the copy's directory.
	Dir string
}

// SignerState is who vouches for a copy (CONTRACT.md, Plugins, Plugin
// approval, Signer states).
type SignerState string

// The signer states.
const (
	// SignerKnown: the manifest's .sig names a publisher key built into the
	// engine, passes its schema and verifies. Verified.SignerKeyID is that
	// key's id.
	SignerKnown SignerState = "KNOWN"
	// SignerUnknown: everything else. With RequireApproval that is no .sig,
	// a .sig that fails its schema, or one naming a key the engine does not
	// have built in, and Verified.SignerKeyID is empty: such a key id cannot
	// be checked and could be made up. Without it, the copy was signed by a
	// key from the person's trust store, whose id SignerKeyID holds.
	SignerUnknown SignerState = "UNKNOWN"
)
