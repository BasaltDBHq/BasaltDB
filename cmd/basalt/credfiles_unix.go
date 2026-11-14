//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// rootCredFiles reaches init --remote's credential files as root. The config
// directory may belong to the engine's user, who could swap agents/ for a
// symlink to send root's reads and writes elsewhere, so agents/ is opened
// once from / without following a link (service.OpenTrustedDir: every
// directory on the way owned by root or the config directory's owner, not
// writable by group or others) and every file is then reached relative to
// it, never by path.
//
// The files belong to the engine's user, the owner of agents/ read from its
// open descriptor (the same rule as the lock files): root hands every file
// it writes, and the lock file, to that owner, so the engine can read its
// credential and promote a .pending one. Root reads files owned by root or
// that owner. In a root-owned agents/ the files stay root's.
type rootCredFiles struct {
	dir *service.TrustedDir
	// owner gets the files root writes; -1 when agents/ is root's.
	owner int
	// self is this process's uid: a file it does not own is checked with
	// checkForeignCredential.
	self int
}

// openRootCredFiles opens dir, the agents directory, as root, making it
// (and the config directory) when missing. trusted is rootTrustedOwner's.
func openRootCredFiles(dir string, trusted int) (credFiles, error) {
	d, err := service.OpenTrustedDir(dir, trusted, true)
	if err != nil {
		return nil, fmt.Errorf("the credential directory %s is refused: %w", dir, err)
	}
	dirUID, err := d.Owner()
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return rootCredFiles{dir: d, owner: credentialOwner(dirUID), self: os.Geteuid()}, nil
}

// rootConfigDir is the config directory init --remote opened as root
// (service.OpenTrustedDir, the trusted owner as openRootCredFiles): it
// locks, reads and writes engine.json relative to it.
type rootConfigDir struct {
	dir     *service.TrustedDir
	trusted int
}

// rootTrustedOwner is the owner root trusts on the way to the config
// directory dir: dir's, or, when it does not exist yet, that of the
// nearest directory above it that does. Read once, before either
// directory is made.
func rootTrustedOwner(dir string) (int, error) { return existingOwner(dir) }

// openRootConfigDir opens dir, the config directory, as root, making it
// when missing.
func openRootConfigDir(dir string, trusted int) (*rootConfigDir, error) {
	d, err := service.OpenTrustedDir(dir, trusted, true)
	if err != nil {
		return nil, fmt.Errorf("the config directory %s is refused: %w", dir, err)
	}
	return &rootConfigDir{dir: d, trusted: trusted}, nil
}

// upsert is config.UpsertAgentVault on the config file name, relative to
// the opened directory, the file checked as the hardened read checks it and
// written owned by the directory's owner.
func (d *rootConfigDir) upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error) {
	dirUID, err := d.dir.Owner()
	if err != nil {
		return config.VaultWritten{}, err
	}
	// engine.json goes to the config directory's owner (the engine's user
	// in service mode), as the files in agents/ do, so the engine can read
	// it; never to root.
	return config.UpsertAgentVaultAt(d.dir, name, func(f *os.File) error { return checkConfigFile(f, d.trusted) }, credentialOwner(dirUID), s, a)
}

func (d *rootConfigDir) close() { _ = d.dir.Close() }

// rootEngineKey is the engine's public key for a root init --remote: the
// key file in the engine's state directory, read or (when there is none)
// created relative to that directory, opened from / without following a
// link anyone but root controls. stateDir comes from engine.json, which
// the config directory's owner may write, so it is trusted no further than
// the config directory: every directory on the way must be owned by root
// or that owner (cfg.trusted), the state directory itself by the config
// directory's owner, and it is never made here (the service manager makes
// it when the service starts). The file must be a regular file with one
// link, owned by that owner, mode 0600 or narrower, and pass the engine's
// own checks (channel.ParseKeyFile). A new one is given to that owner
// before it appears under its name, so the engine loads it as its own; one
// made meanwhile by the engine is kept.
func rootEngineKey(stateDir string, cfg *rootConfigDir, now func() time.Time) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("the config directory is not open")
	}
	want, err := cfg.dir.Owner()
	if err != nil {
		return nil, err
	}
	d, err := service.OpenTrustedDir(stateDir, cfg.trusted, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("the state directory %s does not exist yet; start the engine's service once (it makes it), then run basalt init --remote again", stateDir)
	}
	if err != nil {
		return nil, fmt.Errorf("the state directory %s is refused: %w", stateDir, err)
	}
	defer d.Close()
	if owner, err := d.Owner(); err != nil {
		return nil, err
	} else if owner != want {
		return nil, fmt.Errorf("the state directory %s is owned by uid %d, not uid %d (the owner of the config directory %s)", stateDir, owner, want, cfg.dir.Path())
	}
	dirUID, err := d.Owner()
	if err != nil {
		return nil, err
	}
	for range 2 {
		keys, err := readRootKeyFile(d, dirUID)
		if !errors.Is(err, fs.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return keys.PublicKeySPKI(), nil
		}
		raw, keys, err := channel.NewKeyFile(now)
		if err != nil {
			return nil, err
		}
		err = d.CreateFile(channel.KeyFileName, raw, channel.KeyFileMode, credentialOwner(dirUID))
		clear(raw)
		if err == nil {
			return keys.PublicKeySPKI(), nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("the engine's key file keeps changing; run basalt init --remote again")
}

// readRootKeyFile reads the key file in the state directory d, owned by
// dirUID: an error wrapping fs.ErrNotExist when there is none.
func readRootKeyFile(d *service.TrustedDir, dirUID int) (*channel.EngineKeys, error) {
	f, err := config.OpenPlainAt(d, channel.KeyFileName, func(f *os.File) error {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !ok:
			return errors.New("cannot read the key file's owner")
		case int(st.Uid) != dirUID:
			return fmt.Errorf("%s is owned by uid %d, not uid %d (the owner of %s)", f.Name(), st.Uid, dirUID, d.Path())
		case fi.Mode().Perm()&0o077 != 0:
			return fmt.Errorf("%s is mode %o; it must be readable by the engine's user only (0600)", f.Name(), fi.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, rootKeyFileMax+1))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return channel.ParseKeyFile(f.Name(), raw)
}

// rootKeyFileMax bounds what root reads of the key file (a valid one is
// well under 1 KiB; ParseKeyFile refuses more than 8 KiB).
const rootKeyFileMax = 8 << 10

// credentialOwner is who gets the credential files root writes in a
// directory dirUID owns: that owner, never root (-1: keep root's).
func credentialOwner(dirUID int) int {
	if dirUID <= 0 {
		return -1
	}
	return dirUID
}

// ownedBy accepts a credential file owned by this process's user or by the
// directory's owner, the engine's user root hands them to.
func (r rootCredFiles) ownedBy(uid uint32) (bool, string) {
	if (r.self >= 0 && uint64(uid) == uint64(r.self)) || (r.owner >= 0 && uint64(uid) == uint64(r.owner)) {
		return true, ""
	}
	if r.owner < 0 {
		return false, "root"
	}
	return false, fmt.Sprintf("root or uid %d (the owner of %s)", r.owner, r.dir.Path())
}

// existingOwner is the owner of path or, when it does not exist, of the
// nearest directory above it that does, not following a link.
func existingOwner(path string) (int, error) {
	for {
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) && filepath.Dir(path) != path {
			path = filepath.Dir(path)
			continue
		}
		if err != nil {
			return 0, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, errors.New("cannot read the directory's owner")
		}
		return int(st.Uid), nil
	}
}

// name is path's file name, refusing a path outside the opened directory.
func (r rootCredFiles) name(path string) (string, error) {
	if filepath.Dir(path) != r.dir.Path() {
		return "", fmt.Errorf("%s is not in %s", path, r.dir.Path())
	}
	return filepath.Base(path), nil
}

func (r rootCredFiles) lock(path string) (func(), error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	// A lock file root makes, or finds root's, goes to agents/' owner (the
	// engine's user), as config.LockFile does, so the engine can open it.
	unlock, err := config.LockAt(r.dir, name)
	if errors.Is(err, config.ErrLocked) {
		return nil, fmt.Errorf("another basalt init --remote is running for this agent, or the engine is finishing its setup (%s is locked); run it again in a moment", path)
	}
	return unlock, err
}

func (r rootCredFiles) open(path string) (*os.File, error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	return r.dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func (r rootCredFiles) read(path string) (string, os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	dsn, fi, err := readCredentialFrom(f, r.ownedBy)
	if err != nil {
		return "", nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || r.self < 0 || uint64(st.Uid) != uint64(r.self) {
		if err := checkForeignCredential(dsn); err != nil {
			return "", nil, fmt.Errorf("it belongs to the owner of %s, not root: %w", r.dir.Path(), err)
		}
	}
	return dsn, fi, nil
}

// foreignCredentialKeys are the only parameters root takes from a
// credential file it did not write. pgx reads files for the caller from
// others (passfile, service, servicefile, sslkey, sslcert, sslrootcert,
// sslcrl), so root, connecting with a string the engine's user wrote, would
// read root-only files for that user, or block on a FIFO it names.
var foreignCredentialKeys = map[string]bool{
	"sslmode":                 true,
	"sslnegotiation":          true,
	"sslsni":                  true,
	"channel_binding":         true,
	"require_auth":            true,
	"target_session_attrs":    true,
	"connect_timeout":         true,
	"application_name":        true,
	"min_protocol_version":    true,
	"max_protocol_version":    true,
	"default_query_exec_mode": true,
}

// foreignURLKeys are the URL parts pgx reads as keys besides the
// parameters: who logs in, where, and the database.
var foreignURLKeys = []string{"user", "password", "host", "port", "dbname"}

// errForeignCredential is the refusal of a credential string root does not
// take; it never echoes the string, which holds a password.
var errForeignCredential = errors.New("as root, basalt init --remote takes from it only a postgres:// or postgresql:// URL " +
	"with a password, no # or ;, and only the parameters " + strings.Join(sortedKeys(foreignCredentialKeys), ", ") +
	"; run basalt init --remote as that user (sudo -u <user>), or fix the file")

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// checkForeignCredential accepts, from a credential file root did not
// write, only what pgx reads no file for: a URL with an exact lower-case
// postgres:// or postgresql:// prefix (pgx parses any other string as
// keyword/value), no '#' or ';' (where Go's and pgx's URL parsers
// disagree), a password (without one pgx falls back to root's ~/.pgpass),
// and only foreignCredentialKeys. pgx's own parser is the authority, with
// ConnStringAllowedKeys refusing any other key before it touches the file
// system; it must then agree with Go's parse on the host, port, database
// and password, which is what the rest of init --remote reads.
func checkForeignCredential(dsn string) error {
	if (!strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://")) ||
		strings.ContainsAny(dsn, "#;") || strings.ContainsFunc(dsn, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errForeignCredential
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return errForeignCredential
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return errForeignCredential
	}
	for k := range u.Query() {
		if !foreignCredentialKeys[k] {
			return errForeignCredential
		}
	}
	allowed := append(sortedKeys(foreignCredentialKeys), foreignURLKeys...)
	cfg, err := pgconn.ParseConfigWithOptions(dsn, pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowed})
	if err != nil {
		return errForeignCredential
	}
	port := uint16(defaultPostgresPort)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return errForeignCredential
		}
		port = uint16(n)
	}
	if cfg.Password != pw || cfg.Host != u.Hostname() || cfg.Port != port ||
		cfg.Database != strings.TrimPrefix(u.Path, "/") {
		return errForeignCredential
	}
	for _, fb := range cfg.Fallbacks {
		// sslmode=prefer tries TLS then plain, to the same host and port.
		if fb.Host != cfg.Host || fb.Port != cfg.Port {
			return errForeignCredential
		}
	}
	return nil
}

// defaultPostgresPort is the port a URL without one connects to.
const defaultPostgresPort = 5432

func (r rootCredFiles) stat(path string) (os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func (r rootCredFiles) write(path string, data []byte) error {
	name, err := r.name(path)
	if err != nil {
		return err
	}
	return r.dir.WriteFile(name, data, config.FileMode, r.owner)
}

func (r rootCredFiles) rename(from, to string) error {
	a, err := r.name(from)
	if err != nil {
		return err
	}
	b, err := r.name(to)
	if err != nil {
		return err
	}
	return r.dir.Rename(a, b)
}

func (r rootCredFiles) close() { _ = r.dir.Close() }
