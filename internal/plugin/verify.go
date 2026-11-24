package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// whyFilesNameManifest: a listed file would overwrite the manifest or its
// signature in the copy.
const whyFilesNameManifest = "files names the manifest or its signature"

// Patterns of an entry key and an installed copy's directory name
// (api/plugin/config.schema.json).
var (
	instancePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Verify checks the installed copy of entry key at
// <root>/<name>/<instance>/<manifestSHA256>/, as the engine does at every
// start (CONTRACT.md, Plugins, Signing and the trust store, Verification),
// in this order:
//  1. the path rule, from "/" down to every file in the copy and to every
//     key in the trust store;
//  2. the manifest's SHA-256 is manifestSHA256;
//  3. the signature file is well formed, names a trusted key and verifies
//     over the context line and the manifest's exact bytes; with
//     RequireApproval a copy with no known signer passes this step, and a
//     .sig that names a built-in key must still verify (signerOf);
//  4. the manifest passes ParseManifest and names the entry's plugin;
//  5. for a local plugin every listed file is a regular file with its
//     stated hash; the copy holds nothing else besides the manifest and
//     its signature.
//
// A failure is a *VerifyError; the entry must then not be started, and
// status shows PLUGIN_NOT_TRUSTED for its agents.
func Verify(root string, key pluginmodel.EntryKey, manifestSHA256 string, trust TrustStore, mode pluginmodel.Mode, opts ...Option) (pluginmodel.Verified, error) {
	owner, err := requiredOwner(mode)
	if err != nil {
		return pluginmodel.Verified{}, err
	}
	if err := trust.matches(owner); err != nil {
		return pluginmodel.Verified{}, err
	}
	if err := checkKey(key); err != nil {
		return pluginmodel.Verified{}, err
	}
	if !sha256Pattern.MatchString(manifestSHA256) {
		return pluginmodel.Verified{}, &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: root, Why: "the entry's manifestSha256 is not lowercase hex SHA-256"}
	}
	return verifyCopy(root, key, manifestSHA256, manifestSHA256, trust, owner, optionsOf(opts))
}

func checkKey(key pluginmodel.EntryKey) error {
	if !namePattern.MatchString(key.Name) {
		return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedBadManifest, File: ManifestFile, Why: "the plugin's name is not a plugin name"}
	}
	if !instancePattern.MatchString(key.Instance) {
		return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedBadManifest, File: key.Name, Why: "the instance must be lowercase letters, digits and underscores, starting with a letter"}
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
func verifyCopy(root string, key pluginmodel.EntryKey, dirName, wantSHA string, trust TrustStore, owner uint32, o options) (pluginmodel.Verified, error) {
	nameDir := filepath.Join(root, key.Name)
	instDir := filepath.Join(nameDir, key.Instance)
	dir := filepath.Join(instDir, dirName)

	// 1. The path rule, for the copy and for the trust store.
	if err := checkUnder(owner, root, nameDir, instDir, dir); err != nil {
		return pluginmodel.Verified{}, err
	}
	entries, err := walkCopy(dir, owner)
	if err != nil {
		return pluginmodel.Verified{}, err
	}
	if err := trust.check(); err != nil {
		return pluginmodel.Verified{}, err
	}

	// 2. The manifest's hash.
	manifestPath := filepath.Join(dir, ManifestFile)
	manifest, err := readNoFollow(manifestPath, MaxManifestBytes)
	if err != nil {
		return pluginmodel.Verified{}, err
	}
	sum := sha256.Sum256(manifest)
	sha := hex.EncodeToString(sum[:])
	if wantSHA != "" && sha != wantSHA {
		return pluginmodel.Verified{}, &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: manifestPath, Why: "its SHA-256 is not the entry's manifestSha256"}
	}

	// 3. The signature.
	signer, keyID, err := verifySignature(dir, manifest, entries, trust, o)
	if err != nil {
		return pluginmodel.Verified{}, err
	}

	// 4. The manifest's rules.
	m, err := ParseManifest(manifest)
	if err != nil {
		return pluginmodel.Verified{}, inFile(err, manifestPath)
	}
	if m.Name != key.Name {
		return pluginmodel.Verified{}, &pluginmodel.VerifyError{Reason: pluginmodel.RefusedBadManifest, File: manifestPath, Why: "the manifest names another plugin than the entry"}
	}

	// 5. The files, and nothing else.
	if err := checkContents(dir, m, entries, o.requireApproval); err != nil {
		return pluginmodel.Verified{}, err
	}
	for _, rel := range slices.Sorted(maps.Keys(m.Files)) {
		if err := checkFileHash(filepath.Join(dir, filepath.FromSlash(rel)), m.Files[rel]); err != nil {
			return pluginmodel.Verified{}, err
		}
	}
	return pluginmodel.Verified{Manifest: m, ManifestSHA256: sha, Signer: signer, SignerKeyID: keyID, Dir: dir}, nil
}

// verifySignature reads the copy's .sig and works out its signer
// (signerOf). With approval a copy whose walk found no .sig is unsigned;
// without it a missing .sig is refused when it is read, as before.
func verifySignature(dir string, manifest []byte, entries []copyEntry, trust TrustStore, o options) (pluginmodel.SignerState, string, error) {
	sigPath := filepath.Join(dir, SignatureFile)
	if o.requireApproval && !hasFile(entries, SignatureFile) {
		return signerOf(sigPath, manifest, nil, false, trust, o)
	}
	raw, err := readNoFollow(sigPath, MaxSignatureFileBytes)
	if err != nil {
		return "", "", err
	}
	return signerOf(sigPath, manifest, raw, true, trust, o)
}

// hasFile reports whether the walk of a copy found rel, of any kind.
func hasFile(entries []copyEntry, rel string) bool {
	for _, e := range entries {
		if e.rel == rel {
			return true
		}
	}
	return false
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
		return "", &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: sigPath, Why: "the signature does not verify over the manifest"}
	}
	return keyID, nil
}

// inFile sets a refusal's file to the full path when it named only the
// file's base name.
func inFile(err error, full string) error {
	var ve *pluginmodel.VerifyError
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
			return pluginmodel.PathRefusal(p, "cannot be read")
		}
		if p == dir {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return pluginmodel.PathRefusal(p, "cannot be read")
		}
		if err := checkStrictInfo(p, fi, owner); err != nil {
			return err
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return pluginmodel.PathRefusal(p, "is not a regular file")
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return pluginmodel.PathRefusal(p, "cannot be read")
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
// files and the directories that lead to them, and nothing else. With
// sigOptional (an entry that requires approval) the signature may be
// missing.
func checkContents(dir string, m pluginmodel.Manifest, entries []copyEntry, sigOptional bool) error {
	wantFiles := map[string]bool{ManifestFile: true, SignatureFile: true}
	wantDirs := map[string]bool{}
	for rel := range m.Files {
		if rel == ManifestFile || rel == SignatureFile {
			return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedBadManifest, File: filepath.Join(dir, ManifestFile), Why: whyFilesNameManifest}
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
			return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: full, Why: "is not in the manifest's files"}
		}
	}
	for rel := range wantFiles {
		if !seen[rel] && (rel != SignatureFile || !sigOptional) {
			return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: filepath.Join(dir, filepath.FromSlash(rel)), Why: "is missing"}
		}
	}
	return nil
}

// checkFileHash reads a listed file once, refusing a symlink or anything not
// regular, and compares its SHA-256 with the manifest's.
func checkFileHash(p, want string) error {
	f, err := os.OpenFile(p, noFollowFlags(), 0)
	if err != nil {
		return pluginmodel.PathRefusal(p, "cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return pluginmodel.PathRefusal(p, "is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return pluginmodel.PathRefusal(p, "cannot be read")
	}
	if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != want {
		return &pluginmodel.VerifyError{Reason: pluginmodel.RefusedNotTrusted, File: p, Why: "its SHA-256 is not the one the manifest states"}
	}
	return nil
}
