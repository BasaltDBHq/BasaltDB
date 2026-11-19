package plugin

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// trustFileExt is a trusted key's file extension: <keyId>.pem.
const trustFileExt = ".pem"

// Modes of the trust store's directory and key files.
const (
	dirMode     = 0o755
	keyFileMode = 0o644
)

// TrustStore is the set of keys a manifest signature may name: the Basalt
// publisher keys built into the binary and the keys the person added to
// plugin-trust/, in TrustDir (CONTRACT.md, Plugins, Signing and the trust
// store). It reads the directory at each use, so a key added or removed is
// seen by the next verification.
type TrustStore struct {
	dir      string
	owner    uint32
	embedded map[string]*ecdsa.PublicKey
}

// NewTrustStore is the trust store of an engine run in mode on goos, whose
// engine.json is in configDir: TrustDir(mode, goos, configDir), with the
// owner the path rule requires in that mode.
func NewTrustStore(mode Mode, goos, configDir string) (TrustStore, error) {
	owner, err := mode.owner()
	if err != nil {
		return TrustStore{}, err
	}
	dir, err := TrustDir(mode, goos, configDir)
	if err != nil {
		return TrustStore{}, err
	}
	embedded, err := embeddedKeys()
	if err != nil {
		return TrustStore{}, err
	}
	return TrustStore{dir: dir, owner: owner, embedded: embedded}, nil
}

// Dir is the trust store's directory, TrustDir.
func (t TrustStore) Dir() string { return t.dir }

// errTrustMode: the trust store was made for another engine mode than the
// one verification runs in, so it would check another owner.
var errTrustMode = errors.New("plugin: the trust store was made for another engine mode")

// matches refuses a trust store made for another mode, or not made by
// NewTrustStore, so one check never mixes two required owners.
func (t TrustStore) matches(owner uint32) error {
	if t.dir == "" || t.owner != owner {
		return errTrustMode
	}
	return nil
}

// embeddedKeys parses the built-in publisher keys and indexes them by the
// id computed from each.
func embeddedKeys() (map[string]*ecdsa.PublicKey, error) {
	out := make(map[string]*ecdsa.PublicKey, len(publisherKeys))
	for i, k := range publisherKeys {
		pub, id, err := ParsePublicKey([]byte(k))
		if err != nil {
			return nil, fmt.Errorf("plugin: built-in publisher key %d: %w", i, err)
		}
		out[id] = pub
	}
	return out, nil
}

// BuiltInKey reports whether keyID is one of the publisher keys built into
// the engine, which every trust store holds and no ledger records.
func BuiltInKey(keyID string) bool {
	keys, err := builtInKeys()
	if err != nil {
		return false
	}
	_, ok := keys[keyID]
	return ok
}

// builtInKeys parses the built-in keys once.
var builtInKeys = sync.OnceValues(embeddedKeys)

// check applies the path rule to the trust store: every directory from "/"
// to plugin-trust/, and each entry in it. A trust store that does not exist
// holds no keys and passes.
func (t TrustStore) check() error {
	if _, err := os.Lstat(t.dir); errors.Is(err, fs.ErrNotExist) {
		// No keys are stored; the directories that exist above it still
		// follow the rule, so none can be swapped in before a key is read.
		_, err := checkExisting(t.dir, t.dir, t.owner)
		return err
	}
	if err := checkUnder(t.owner, t.dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return pathRefusal(t.dir, "cannot be read")
	}
	for _, e := range entries {
		if _, err := checkStrict(filepath.Join(t.dir, e.Name()), t.owner); err != nil {
			return err
		}
	}
	return nil
}

// key is the trusted key named keyID. A built-in key is found by its
// computed id. A stored key is the file whose name is exactly
// <keyID>.pem, found by listing the directory so a case-insensitive file
// system cannot alias another name to it; it must hold exactly one P-256
// PEM PUBLIC KEY whose computed id is keyID. Anything else is not trusted.
func (t TrustStore) key(keyID string) (*ecdsa.PublicKey, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, &VerifyError{Reason: RefusedNotTrusted, File: SignatureFile, Why: "the signature's keyId is not a key id"}
	}
	if pub, ok := t.embedded[keyID]; ok {
		return pub, nil
	}
	notTrusted := &VerifyError{Reason: RefusedNotTrusted, File: SignatureFile, Why: "the signature names a key that is not trusted"}
	entries, err := os.ReadDir(t.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, notTrusted
	}
	if err != nil {
		return nil, pathRefusal(t.dir, "cannot be read")
	}
	name := keyID + trustFileExt
	for _, e := range entries {
		if e.Name() != name {
			continue
		}
		path := filepath.Join(t.dir, name)
		b, err := readOwned(path, MaxKeyFileBytes, t.owner)
		if err != nil {
			return nil, err
		}
		pub, id, err := ParsePublicKey(b)
		if err != nil {
			return nil, &VerifyError{Reason: RefusedNotTrusted, File: path, Why: "is not a trusted key: " + err.Error()}
		}
		if id != keyID {
			return nil, &VerifyError{Reason: RefusedNotTrusted, File: path, Why: "is not a trusted key: its name is not the id of the key it holds"}
		}
		return pub, nil
	}
	return nil, notTrusted
}

// Add trusts the public key in pemBytes: it writes the key to
// plugin-trust/<keyId>.pem, the id computed from the key, creating the
// directory when needed, and checks the path rule over the store first. A
// key that is already trusted changes nothing and reports added false. The
// caller asks the person to confirm the key id first, refuses on an
// agent-operated engine, and records PLUGIN_TRUST_ADDED when added is true.
func (t TrustStore) Add(pemBytes []byte) (keyID string, added bool, err error) {
	pub, id, err := ParsePublicKey(pemBytes)
	if err != nil {
		return "", false, err
	}
	if _, ok := t.embedded[id]; ok {
		return id, false, nil
	}
	if err := ensureDir(t.dir, t.dir, t.owner); err != nil {
		return "", false, err
	}
	if err := t.check(); err != nil {
		return "", false, err
	}
	if have, err := t.key(id); err == nil && have.Equal(pub) {
		return id, false, nil
	}
	canonical, err := MarshalPublicKey(pub)
	if err != nil {
		return "", false, err
	}
	if err := writeFileAtomic(t.dir, id+trustFileExt, canonical, keyFileMode); err != nil {
		return "", false, err
	}
	return id, true, nil
}

// ensureDir creates dir, which is boundary or lies below it, with any
// missing parents. It first applies the path rule to the nearest directory
// that exists (strictly when it is at or below boundary, as above a root
// otherwise), so no directory is created inside one another user could
// write, and only then creates each missing directory with mode 0755, set
// explicitly so a umask cannot leave group or other write on it. A
// directory that appears meanwhile is refused, never reused.
func ensureDir(boundary, dir string, owner uint32) error {
	boundary, dir = filepath.Clean(boundary), filepath.Clean(dir)
	if !within(boundary, dir) {
		return pathRefusal(dir, "is not inside "+boundary)
	}
	missing, err := checkExisting(boundary, dir, owner)
	if err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		// The parent passed the path rule, so only its owner or root can
		// put anything at this name; Mkdir fails rather than reuse it.
		if err := os.Mkdir(missing[i], dirMode); err != nil {
			return pathRefusal(missing[i], "cannot be created")
		}
		if err := os.Chmod(missing[i], dirMode); err != nil {
			return pathRefusal(missing[i], "cannot be set to mode 0755")
		}
	}
	return nil
}

// checkExisting applies the path rule to the nearest directory at or above
// dir that exists (strictly when it is at or below boundary, as above a
// root otherwise) and returns the missing directories below it, deepest
// first.
func checkExisting(boundary, dir string, owner uint32) ([]string, error) {
	boundary, dir = filepath.Clean(boundary), filepath.Clean(dir)
	if !within(boundary, dir) {
		return nil, pathRefusal(dir, "is not inside "+boundary)
	}
	var missing []string
	existing := dir
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, pathRefusal(existing, "cannot be read")
		}
		missing = append(missing, existing)
		parent := filepath.Dir(existing)
		if parent == existing {
			return nil, pathRefusal(existing, "cannot be read")
		}
		existing = parent
	}
	if within(boundary, existing) {
		if err := checkUnder(owner, chain(boundary, existing)...); err != nil {
			return nil, err
		}
	} else if err := checkAbove(filepath.Join(existing, "x"), owner); err != nil {
		return nil, err
	}
	return missing, nil
}

// within reports whether p is base or lies below it.
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// chain is base, then each directory from base down to p, p included. p is
// base or lies below it.
func chain(base, p string) []string {
	out := []string{base}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." {
		return out
	}
	cur := base
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		cur = filepath.Join(cur, part)
		out = append(out, cur)
	}
	return out
}

// writeFileAtomic writes name in dir through a temporary file and a rename,
// with mode set explicitly.
func writeFileAtomic(dir, name string, b []byte, mode os.FileMode) error {
	path := filepath.Join(dir, name)
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return pathRefusal(path, "cannot be written")
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return pathRefusal(path, "cannot be written")
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return pathRefusal(path, "cannot be written")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return pathRefusal(path, "cannot be written")
	}
	if err := f.Close(); err != nil {
		return pathRefusal(path, "cannot be written")
	}
	if err := os.Rename(tmp, path); err != nil {
		return pathRefusal(path, "cannot be written")
	}
	ok = true
	return nil
}

// readOwned is readNoFollow that also applies the path rule to the file it
// opened: owned by owner and writable by no one else.
func readOwned(path string, limit int64, owner uint32) ([]byte, error) {
	f, err := os.OpenFile(path, noFollowFlags, 0)
	if err != nil {
		return nil, pathRefusal(path, "cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, pathRefusal(path, "cannot be read")
	}
	if err := checkStrictInfo(path, fi, owner); err != nil {
		return nil, err
	}
	return readOpened(f, fi, path, limit)
}

// readNoFollow reads a regular file, refusing a symlink as its last
// component, a file larger than limit, and anything not regular. Errors name
// the path, never the contents.
func readNoFollow(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, noFollowFlags, 0)
	if err != nil {
		return nil, pathRefusal(path, "cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, pathRefusal(path, "cannot be read")
	}
	return readOpened(f, fi, path, limit)
}

// readOpened reads an opened file that must be regular and at most limit
// bytes.
func readOpened(f *os.File, fi fs.FileInfo, path string, limit int64) ([]byte, error) {
	if !fi.Mode().IsRegular() {
		return nil, pathRefusal(path, "is not a regular file")
	}
	if fi.Size() > limit {
		return nil, pathRefusal(path, "is too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, pathRefusal(path, "cannot be read")
	}
	if int64(len(b)) > limit {
		return nil, pathRefusal(path, "is too large")
	}
	return b, nil
}
