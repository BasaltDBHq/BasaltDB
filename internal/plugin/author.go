package plugin

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// The author commands, basalt plugin keygen and sign (CONTRACT.md, Plugins,
// Signing and the trust store, Author commands). Neither reads or writes
// engine.json, the trust store or the ledger, and neither prints, logs or
// returns a private key's bytes: errors name the file and the rule only.

// Files keygen writes.
const (
	PrivateKeyExt  = ".key"
	PublicKeyExt   = ".pub"
	privateKeyMode = 0o600
	publicKeyMode  = 0o644
	keyDirMode     = 0o700
	// groupOtherAccess are the bits a private key file must not have.
	groupOtherAccess = 0o077
)

// KeyPairFiles are the files WriteKeyPair wrote.
type KeyPairFiles struct {
	KeyID       string
	PrivatePath string
	PublicPath  string
}

// WriteKeyPair makes a new P-256 key pair and writes it to
// dir/<keyId>.key (PKCS#8, mode 0600) and dir/<keyId>.pub. It creates dir
// (mode 0700) when missing and never overwrites a file: when either file
// exists nothing is written.
func WriteKeyPair(dir string) (KeyPairFiles, error) {
	priv, err := GenerateKey()
	if err != nil {
		return KeyPairFiles{}, err
	}
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return KeyPairFiles{}, err
	}
	privPEM, err := MarshalPrivateKey(priv)
	if err != nil {
		return KeyPairFiles{}, err
	}
	pubPEM, err := MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return KeyPairFiles{}, err
	}
	if err := os.MkdirAll(dir, keyDirMode); err != nil {
		return KeyPairFiles{}, fmt.Errorf("key directory %s cannot be created", dir)
	}
	out := KeyPairFiles{KeyID: id, PrivatePath: filepath.Join(dir, id+PrivateKeyExt), PublicPath: filepath.Join(dir, id+PublicKeyExt)}
	for _, p := range []string{out.PrivatePath, out.PublicPath} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return KeyPairFiles{}, fmt.Errorf("%s already exists; keygen never overwrites a file", p)
		}
	}
	if err := writeExclusive(out.PrivatePath, privPEM, privateKeyMode); err != nil {
		return KeyPairFiles{}, err
	}
	if err := writeExclusive(out.PublicPath, pubPEM, publicKeyMode); err != nil {
		_ = os.Remove(out.PrivatePath)
		return KeyPairFiles{}, err
	}
	return out, nil
}

// writeExclusive creates p, which must not exist (O_EXCL: never through a
// symlink), with mode set explicitly whatever the umask.
func writeExclusive(p string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; keygen never overwrites a file", p)
	}
	if err != nil {
		return fmt.Errorf("%s cannot be created", p)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(p)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("%s cannot be set to mode %o", p, mode)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("%s cannot be written", p)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("%s cannot be written", p)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%s cannot be written", p)
	}
	ok = true
	return nil
}

// ReadSigningKey reads a private key file for signing. It opens the file
// without following a symlink and checks the opened file before reading
// it: a regular file, owned by this process's user, with no access for
// group or others (0600 or narrower). Errors name the file and the rule,
// never its contents.
func ReadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	f, err := os.OpenFile(path, noFollowFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("key file %s cannot be opened, or is a symlink", path)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	me, err := currentUID()
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	if uid != me {
		return nil, fmt.Errorf("key file %s is owned by another user; it must be yours", path)
	}
	if perm := fi.Mode().Perm(); perm&groupOtherAccess != 0 {
		return nil, fmt.Errorf("key file %s is mode %04o; it must be readable by you only (chmod 600)", path, perm)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("key file %s cannot be read", path)
	}
	if len(b) > MaxKeyFileBytes {
		return nil, fmt.Errorf("key file %s is larger than %d bytes", path, MaxKeyFileBytes)
	}
	priv, err := ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	return priv, nil
}

// SignDir checks the plugin in dir and writes dir/basalt-plugin.json.sig
// signed by priv: the manifest must pass ParseManifest, and every file in
// its files must be a regular file (not a symlink) with its stated hash.
// It returns the signature file's path and the signer's key id. Errors are
// *VerifyError for a manifest or file rule, naming the file and the rule.
func SignDir(dir string, priv *ecdsa.PrivateKey) (sigPath, keyID string, err error) {
	manifestPath := filepath.Join(dir, ManifestFile)
	manifest, err := readNoFollow(manifestPath, MaxManifestBytes)
	if err != nil {
		return "", "", err
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return "", "", inFile(err, manifestPath)
	}
	if _, ok := m.Files[ManifestFile]; ok {
		return "", "", &VerifyError{Reason: RefusedBadManifest, File: manifestPath, Why: whyFilesNameManifest}
	}
	if _, ok := m.Files[SignatureFile]; ok {
		return "", "", &VerifyError{Reason: RefusedBadManifest, File: manifestPath, Why: whyFilesNameManifest}
	}
	for _, rel := range sortedKeys(m.Files) {
		if err := checkFileHash(filepath.Join(dir, filepath.FromSlash(rel)), m.Files[rel]); err != nil {
			return "", "", err
		}
	}
	sig, err := SignManifest(manifest, priv)
	if err != nil {
		return "", "", err
	}
	if keyID, err = KeyID(&priv.PublicKey); err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(dir, SignatureFile, sig, keyFileMode); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, SignatureFile), keyID, nil
}
