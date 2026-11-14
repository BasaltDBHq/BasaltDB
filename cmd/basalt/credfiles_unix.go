//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"

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
// (and the config directory) when missing. The trusted owner is the config
// directory's, or, when it does not exist yet, that of the nearest
// directory above it that does.
func openRootCredFiles(dir string) (credFiles, error) {
	trusted, err := existingOwner(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
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
	dirUID, err := r.dir.Owner()
	if err != nil {
		return nil, err
	}
	f, err := r.dir.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NONBLOCK, config.FileMode)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	// A lock file root makes, or finds root's, goes to agents/' owner (the
	// engine's user), as config.LockFile does, so the engine can open it.
	unlock, err := config.LockOpenFile(f, dirUID)
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
