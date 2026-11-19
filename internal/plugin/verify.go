package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
)

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

// whyFilesNameManifest: a listed file would overwrite the manifest or its
// signature in the copy.
const whyFilesNameManifest = "files names the manifest or its signature"

// Verified is a plugin copy that passed every check.
type Verified struct {
	// Manifest is the copy's manifest.
	Manifest Manifest
	// ManifestSHA256 is the SHA-256 of the manifest's exact bytes, lowercase
	// hex: the entry's manifestSha256 and the copy's directory name.
	ManifestSHA256 string
	// SignerKeyID is the id of the key that signed the manifest.
	SignerKeyID string
	// Dir is the copy's directory.
	Dir string
}

// Patterns of an entry key and an installed copy's directory name
// (api/plugin/config.schema.json).
var (
	instancePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DefaultInstance is an entry's instance when engine.json names none.
const DefaultInstance = "default"

// Verify checks the installed copy of entry key at
// <root>/<name>/<instance>/<manifestSHA256>/, as the engine does at every
// start (CONTRACT.md, Plugins, Signing and the trust store, Verification),
// in this order:
//  1. the path rule, from "/" down to every file in the copy and to every
//     key in the trust store;
//  2. the manifest's SHA-256 is manifestSHA256;
//  3. the signature file is well formed, names a trusted key and verifies
//     over the context line and the manifest's exact bytes;
//  4. the manifest passes ParseManifest and names the entry's plugin;
//  5. for a local plugin every listed file is a regular file with its
//     stated hash; the copy holds nothing else besides the manifest and
//     its signature.
//
// A failure is a *VerifyError; the entry must then not be started, and
// status shows PLUGIN_NOT_TRUSTED for its agents.
func Verify(root string, key EntryKey, manifestSHA256 string, trust TrustStore, mode Mode) (Verified, error) {
	owner, err := mode.owner()
	if err != nil {
		return Verified{}, err
	}
	if err := trust.matches(owner); err != nil {
		return Verified{}, err
	}
	if err := checkKey(key); err != nil {
		return Verified{}, err
	}
	if !sha256Pattern.MatchString(manifestSHA256) {
		return Verified{}, &VerifyError{Reason: RefusedNotTrusted, File: root, Why: "the entry's manifestSha256 is not lowercase hex SHA-256"}
	}
	return verifyCopy(root, key, manifestSHA256, manifestSHA256, trust, owner)
}

func checkKey(key EntryKey) error {
	if !namePattern.MatchString(key.Name) {
		return &VerifyError{Reason: RefusedBadManifest, File: ManifestFile, Why: "the plugin's name is not a plugin name"}
	}
	if !instancePattern.MatchString(key.Instance) {
		return &VerifyError{Reason: RefusedBadManifest, File: key.Name, Why: "the instance must be lowercase letters, digits and underscores, starting with a letter"}
	}
	return nil
}

// copyEntry is one path in a copy, relative to its directory.
type copyEntry struct {
	rel   string
	isDir bool
}

// verifyCopy checks the copy in <root>/<name>/<instance>/<dirName>. wantSHA
// is the manifest's expected SHA-256, or "" while the copy is a temporary
// one at add.
func verifyCopy(root string, key EntryKey, dirName, wantSHA string, trust TrustStore, owner uint32) (Verified, error) {
	nameDir := filepath.Join(root, key.Name)
	instDir := filepath.Join(nameDir, key.Instance)
	dir := filepath.Join(instDir, dirName)

	// 1. The path rule, for the copy and for the trust store.
	if err := checkUnder(owner, root, nameDir, instDir, dir); err != nil {
		return Verified{}, err
	}
	entries, err := walkCopy(dir, owner)
	if err != nil {
		return Verified{}, err
	}
	if err := trust.check(); err != nil {
		return Verified{}, err
	}

	// 2. The manifest's hash.
	manifestPath := filepath.Join(dir, ManifestFile)
	manifest, err := readNoFollow(manifestPath, MaxManifestBytes)
	if err != nil {
		return Verified{}, err
	}
	sum := sha256.Sum256(manifest)
	sha := hex.EncodeToString(sum[:])
	if wantSHA != "" && sha != wantSHA {
		return Verified{}, &VerifyError{Reason: RefusedNotTrusted, File: manifestPath, Why: "its SHA-256 is not the entry's manifestSha256"}
	}

	// 3. The signature.
	keyID, err := verifySignature(dir, manifest, trust)
	if err != nil {
		return Verified{}, err
	}

	// 4. The manifest's rules.
	m, err := ParseManifest(manifest)
	if err != nil {
		return Verified{}, inFile(err, manifestPath)
	}
	if m.Name != key.Name {
		return Verified{}, &VerifyError{Reason: RefusedBadManifest, File: manifestPath, Why: "the manifest names another plugin than the entry"}
	}

	// 5. The files, and nothing else.
	if err := checkContents(dir, m, entries); err != nil {
		return Verified{}, err
	}
	for _, rel := range sortedKeys(m.Files) {
		if err := checkFileHash(filepath.Join(dir, filepath.FromSlash(rel)), m.Files[rel]); err != nil {
			return Verified{}, err
		}
	}
	return Verified{Manifest: m, ManifestSHA256: sha, SignerKeyID: keyID, Dir: dir}, nil
}

// verifySignature reads the copy's .sig and checks it against the trust
// store and the manifest's exact bytes.
func verifySignature(dir string, manifest []byte, trust TrustStore) (string, error) {
	sigPath := filepath.Join(dir, SignatureFile)
	raw, err := readNoFollow(sigPath, MaxSignatureFileBytes)
	if err != nil {
		return "", err
	}
	return checkSignature(sigPath, manifest, raw, trust)
}

// checkSignature checks a .sig's bytes against the trust store and the
// manifest's exact bytes. Refusals name sigPath.
func checkSignature(sigPath string, manifest, raw []byte, trust TrustStore) (string, error) {
	keyID, sig, err := parseSignatureFile(raw)
	if err != nil {
		return "", inFile(err, sigPath)
	}
	pub, err := trust.key(keyID)
	if err != nil {
		return "", inFile(err, sigPath)
	}
	if !verifyManifestSig(pub, manifest, sig) {
		return "", &VerifyError{Reason: RefusedNotTrusted, File: sigPath, Why: "the signature does not verify over the manifest"}
	}
	return keyID, nil
}

// inFile sets a refusal's file to the full path when it named only the
// file's base name.
func inFile(err error, full string) error {
	var ve *VerifyError
	if errors.As(err, &ve) && ve.File == filepath.Base(full) {
		cp := *ve
		cp.File = full
		return &cp
	}
	return err
}

// walkCopy lists every path in the copy, checking the path rule at each:
// no symlink, owned by owner, writable by no one else.
func walkCopy(dir string, owner uint32) ([]copyEntry, error) {
	var out []copyEntry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return pathRefusal(p, "cannot be read")
		}
		if p == dir {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return pathRefusal(p, "cannot be read")
		}
		if err := checkStrictInfo(p, fi, owner); err != nil {
			return err
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return pathRefusal(p, "is not a regular file")
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return pathRefusal(p, "cannot be read")
		}
		out = append(out, copyEntry{rel: filepath.ToSlash(rel), isDir: fi.IsDir()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// checkContents: the copy holds the manifest, its signature, the listed
// files and the directories that lead to them, and nothing else.
func checkContents(dir string, m Manifest, entries []copyEntry) error {
	wantFiles := map[string]bool{ManifestFile: true, SignatureFile: true}
	wantDirs := map[string]bool{}
	for rel := range m.Files {
		if rel == ManifestFile || rel == SignatureFile {
			return &VerifyError{Reason: RefusedBadManifest, File: filepath.Join(dir, ManifestFile), Why: whyFilesNameManifest}
		}
		wantFiles[rel] = true
		for d := path.Dir(rel); d != "."; d = path.Dir(d) {
			wantDirs[d] = true
		}
	}
	seen := map[string]bool{}
	for _, e := range entries {
		full := filepath.Join(dir, filepath.FromSlash(e.rel))
		switch {
		case e.isDir && wantDirs[e.rel]:
		case !e.isDir && wantFiles[e.rel]:
			seen[e.rel] = true
		default:
			return &VerifyError{Reason: RefusedNotTrusted, File: full, Why: "is not in the manifest's files"}
		}
	}
	for rel := range wantFiles {
		if !seen[rel] {
			return &VerifyError{Reason: RefusedNotTrusted, File: filepath.Join(dir, filepath.FromSlash(rel)), Why: "is missing"}
		}
	}
	return nil
}

// checkFileHash reads a listed file once, refusing a symlink or anything not
// regular, and compares its SHA-256 with the manifest's.
func checkFileHash(p, want string) error {
	f, err := os.OpenFile(p, noFollowFlags, 0)
	if err != nil {
		return pathRefusal(p, "cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return pathRefusal(p, "is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return pathRefusal(p, "cannot be read")
	}
	if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != want {
		return &VerifyError{Reason: RefusedNotTrusted, File: p, Why: "its SHA-256 is not the one the manifest states"}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
