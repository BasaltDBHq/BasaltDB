package pluginhost

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/pluginpath"
)

// Modes of installed files. A file the source ships executable, and the
// command, are 0755; every other file is 0644. No other source mode bit is
// copied.
const (
	installedFileMode = 0o644
	installedExecMode = 0o755
	execBits          = 0o111
	stagingPrefix     = ".staging-"
	oldPrefix         = ".old-"
)

// Staged is a verified temporary copy of a plugin under
// <root>/<name>/<instance>/, not yet in place. The add command shows the
// consent screen from Verified.Manifest, then calls Commit, or Discard when
// the person declines. Its directory is readable by its owner only until
// Commit.
type Staged struct {
	Verified
	Key   EntryKey
	root  string
	owner uint32
	trust TrustStore
	opts  options
	done  bool
}

// Stage copies a plugin from src into a new temporary directory under
// <root>/<name>/<instance>/ and verifies that copy (CONTRACT.md, Plugins,
// Installed copies). It reads the manifest, its signature and each listed
// file from src once, refusing a symlink anywhere below src and anything not
// a regular file, so the copy is exactly what was read; a change to src
// afterwards has no effect. A remote plugin's copy is the manifest and its
// signature only. instance "" is "default". On any failure nothing is left
// behind. With RequireApproval a source with no .sig stages, and its copy
// has none.
func Stage(src, root, instance string, trust TrustStore, mode Mode, opts ...Option) (*Staged, error) {
	o := optionsOf(opts)
	owner, err := pluginpath.Owner(mode)
	if err != nil {
		return nil, err
	}
	if err := trust.matches(owner); err != nil {
		return nil, err
	}
	if instance == "" {
		instance = DefaultInstance
	}
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return nil, pathRefusal(src, "cannot be opened as a directory")
	}
	defer func() { _ = srcRoot.Close() }()

	manifest, err := readSource(srcRoot, src, ManifestFile, MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	// Unsigned only when the .sig does not exist; a symlink, or anything
	// else readSource refuses, is refused as before.
	var sig []byte
	signed := true
	if o.requireApproval {
		if _, err := srcRoot.Lstat(SignatureFile); errors.Is(err, fs.ErrNotExist) {
			signed = false
		}
	}
	if signed {
		sig, err = readSource(srcRoot, src, SignatureFile, MaxSignatureFileBytes)
		if err != nil {
			return nil, err
		}
	}
	// Checked here, in the order verification uses, only to learn the name
	// and the files to copy and to refuse early; every check runs again on
	// the copy.
	if err := trust.check(); err != nil {
		return nil, err
	}
	if _, _, err := signerOf(filepath.Join(src, SignatureFile), manifest, sig, signed, trust, o); err != nil {
		return nil, err
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return nil, inFile(err, filepath.Join(src, ManifestFile))
	}
	key := EntryKey{Name: m.Name, Instance: instance}
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if _, ok := m.Files[ManifestFile]; ok {
		return nil, &VerifyError{Reason: RefusedBadManifest, File: filepath.Join(src, ManifestFile), Why: whyFilesNameManifest}
	}
	if _, ok := m.Files[SignatureFile]; ok {
		return nil, &VerifyError{Reason: RefusedBadManifest, File: filepath.Join(src, ManifestFile), Why: whyFilesNameManifest}
	}

	nameDir := filepath.Join(root, key.Name)
	instDir := filepath.Join(nameDir, key.Instance)
	if err := ensureDir(root, instDir, owner); err != nil {
		return nil, err
	}
	// The path rule holds where the copy is written before anything is
	// written or later removed there.
	if err := checkUnder(owner, root, nameDir, instDir); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(instDir, stagingPrefix)
	if err != nil {
		return nil, pathRefusal(instDir, "cannot hold a temporary copy")
	}
	s := &Staged{Key: key, root: root, owner: owner, trust: trust, opts: o}
	s.Dir = tmp
	if err := s.fill(srcRoot, src, m, manifest, sig, signed); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	v, err := verifyCopy(root, key, filepath.Base(tmp), "", trust, owner, o)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	s.Verified = v
	return s, nil
}

// fill writes the manifest and signature bytes already read (no signature
// when signed is false), and copies each listed file, into the temporary
// copy.
func (s *Staged) fill(srcRoot *os.Root, src string, m Manifest, manifest, sig []byte, signed bool) error {
	if err := writeNew(filepath.Join(s.Dir, ManifestFile), manifest, installedFileMode); err != nil {
		return err
	}
	if signed {
		if err := writeNew(filepath.Join(s.Dir, SignatureFile), sig, installedFileMode); err != nil {
			return err
		}
	}
	command := ""
	if m.Endpoint.Local != nil {
		command = m.Endpoint.Local.Command
	}
	for _, rel := range sortedKeys(m.Files) {
		if err := s.copyFile(srcRoot, src, rel, rel == command); err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies one listed file from the source into the copy.
func (s *Staged) copyFile(srcRoot *os.Root, src, rel string, command bool) error {
	srcPath := filepath.Join(src, filepath.FromSlash(rel))
	if err := noSymlinkBelow(srcRoot, src, rel); err != nil {
		return err
	}
	in, err := srcRoot.OpenFile(filepath.FromSlash(rel), noFollowFlags, 0)
	if err != nil {
		return pathRefusal(srcPath, "cannot be opened, or is a symlink")
	}
	defer func() { _ = in.Close() }()
	fi, err := in.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return pathRefusal(srcPath, "is not a regular file")
	}
	mode := os.FileMode(installedFileMode)
	if command || fi.Mode().Perm()&execBits != 0 {
		mode = installedExecMode
	}
	dst := filepath.Join(s.Dir, filepath.FromSlash(rel))
	if err := mkdirsIn(s.Dir, path.Dir(rel)); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, installedFileMode)
	if err != nil {
		return pathRefusal(dst, "cannot be created")
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return pathRefusal(srcPath, "cannot be read")
	}
	if err := out.Chmod(mode); err != nil {
		_ = out.Close()
		return pathRefusal(dst, "cannot be written")
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return pathRefusal(dst, "cannot be written")
	}
	if err := out.Close(); err != nil {
		return pathRefusal(dst, "cannot be written")
	}
	return nil
}

// noSymlinkBelow refuses a symlink at any component from the source down to
// a listed file, the file included. os.Root already keeps every open inside
// the source; this also refuses a link that stays inside it, and the open
// that follows uses O_NOFOLLOW for a link swapped in meanwhile.
func noSymlinkBelow(srcRoot *os.Root, src, rel string) error {
	parts := strings.Split(rel, "/")
	for i := 1; i <= len(parts); i++ {
		sub := strings.Join(parts[:i], "/")
		fi, err := srcRoot.Lstat(filepath.FromSlash(sub))
		if err != nil {
			return pathRefusal(filepath.Join(src, filepath.FromSlash(sub)), "cannot be read")
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return pathRefusal(filepath.Join(src, filepath.FromSlash(sub)), "is a symlink")
		}
		if i < len(parts) && !fi.IsDir() {
			return pathRefusal(filepath.Join(src, filepath.FromSlash(sub)), "is not a directory")
		}
	}
	return nil
}

// readSource reads one file of the source once: no symlink, regular, at most
// limit bytes.
func readSource(srcRoot *os.Root, src, name string, limit int64) ([]byte, error) {
	p := filepath.Join(src, name)
	if err := noSymlinkBelow(srcRoot, src, name); err != nil {
		return nil, err
	}
	f, err := srcRoot.OpenFile(name, noFollowFlags, 0)
	if err != nil {
		return nil, pathRefusal(p, "cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, pathRefusal(p, "is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, pathRefusal(p, "cannot be read")
	}
	if int64(len(b)) > limit {
		return nil, pathRefusal(p, "is too large")
	}
	return b, nil
}

// mkdirsIn creates rel's directories inside base, each 0755.
func mkdirsIn(base, rel string) error {
	if rel == "." || rel == "" {
		return nil
	}
	cur := base
	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)
		err := os.Mkdir(cur, dirMode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return pathRefusal(cur, "cannot be created")
		}
		if err := os.Chmod(cur, dirMode); err != nil {
			return pathRefusal(cur, "cannot be set to mode 0755")
		}
	}
	return nil
}

// writeNew creates path, which must not exist, with b and mode.
func writeNew(p string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return pathRefusal(p, "cannot be created")
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return pathRefusal(p, "cannot be written")
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return pathRefusal(p, "cannot be written")
	}
	if err := f.Close(); err != nil {
		return pathRefusal(p, "cannot be written")
	}
	return nil
}

// Commit renames the verified copy into place as
// <root>/<name>/<instance>/<manifest-sha256>/ and returns that directory.
// When that directory already exists, verifies and has the same signer
// state and key as the staged copy, it is kept and the temporary copy
// removed; when it fails verification, or has another signer, it is
// replaced, so the copy in place is always the one the consent screen
// showed, signer included. It is verified with Stage's options. With
// RequireApproval it is also kept only when its .sig is the staged one,
// byte for byte, or both have none: two UNKNOWN copies can differ in it.
func (s *Staged) Commit() (string, error) {
	if s.done {
		return "", errors.New("plugin: the staged copy was already committed or discarded")
	}
	s.done = true
	instDir := filepath.Dir(s.Dir)
	final := filepath.Join(instDir, s.ManifestSHA256)
	if err := os.Chmod(s.Dir, dirMode); err != nil {
		_ = os.RemoveAll(s.Dir)
		return "", pathRefusal(s.Dir, "cannot be set to mode 0755")
	}
	if _, err := os.Lstat(final); err == nil {
		kept, verr := verifyCopy(s.root, s.Key, s.ManifestSHA256, s.ManifestSHA256, s.trust, s.owner, s.opts)
		if verr == nil && kept.Signer == s.Signer && kept.SignerKeyID == s.SignerKeyID &&
			(!s.opts.requireApproval || sameSignatureFile(final, s.Dir)) {
			_ = os.RemoveAll(s.Dir)
			s.Verified = kept
			return final, nil
		}
		old := filepath.Join(instDir, oldPrefix+strings.TrimPrefix(filepath.Base(s.Dir), stagingPrefix))
		if err := os.Rename(final, old); err != nil {
			_ = os.RemoveAll(s.Dir)
			return "", pathRefusal(final, "exists, is not the staged copy, and cannot be moved aside")
		}
		if err := os.Rename(s.Dir, final); err != nil {
			// Put the copy that was in place back: an entry may still name it.
			_ = os.Rename(old, final)
			_ = os.RemoveAll(s.Dir)
			return "", pathRefusal(final, "cannot be put in place")
		}
		_ = os.RemoveAll(old)
		s.Dir = final
		return final, nil
	}
	if err := os.Rename(s.Dir, final); err != nil {
		_ = os.RemoveAll(s.Dir)
		return "", pathRefusal(final, "cannot be put in place")
	}
	s.Dir = final
	return final, nil
}

// sameSignatureFile reports whether copies a and b both hold no .sig, or
// hold the same bytes in it.
func sameSignatureFile(a, b string) bool {
	read := func(dir string) ([]byte, bool, bool) {
		p := filepath.Join(dir, SignatureFile)
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			return nil, false, true
		}
		raw, err := readNoFollow(p, MaxSignatureFileBytes)
		return raw, true, err == nil
	}
	ra, hasA, okA := read(a)
	rb, hasB, okB := read(b)
	return okA && okB && hasA == hasB && bytes.Equal(ra, rb)
}

// Discard removes the temporary copy.
func (s *Staged) Discard() error {
	if s.done {
		return nil
	}
	s.done = true
	if err := os.RemoveAll(s.Dir); err != nil {
		return pathRefusal(s.Dir, "cannot be removed")
	}
	return nil
}

// Install stages the plugin in src and commits it, with no consent step in
// between. It returns the installed copy.
func Install(src, root, instance string, trust TrustStore, mode Mode, opts ...Option) (Verified, error) {
	s, err := Stage(src, root, instance, trust, mode, opts...)
	if err != nil {
		return Verified{}, err
	}
	dir, err := s.Commit()
	if err != nil {
		return Verified{}, err
	}
	v := s.Verified
	v.Dir = dir
	return v, nil
}
