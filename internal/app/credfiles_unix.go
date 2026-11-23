//go:build unix

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
)

// rootFiles reaches the files of an engine started as root
// (CONTRACT.md, basalt engine). The config's directory may belong to
// another user, who could swap it or agents/ for a symlink to send root's
// reads and writes elsewhere, so both directories are opened once, from /
// without following a link anyone but root controls (service.TrustedDir:
// every directory on the way owned by root or the config directory's owner,
// not writable by group or others), and every file is then reached
// relative to them, for the engine's lifetime.
type rootFiles struct {
	configDir, agentsDir *osservice.TrustedDir
	configName, name     string
	// trusted is the config directory's owner: the config must be owned
	// by root or that user (config.CheckTrustedConfig).
	trusted int
	// self is this process's uid: a credential file it does not own (the
	// owner of agents/ wrote it) is checked with pgdial.CheckForeignDSN.
	self int
}

// openRootFiles opens the files of agent for a root engine: credFile must
// be the computed agents/<agent>.url (rootCredentialPath).
func openRootFiles(configPath, agent, credFile string) (agentFiles, error) {
	path, err := rootCredentialPath(configPath, agent, credFile)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(configPath)
	trusted, err := ownerOf(dir)
	if err != nil {
		return nil, err
	}
	cd, err := osservice.OpenTrustedDir(dir, trusted, false)
	if err != nil {
		return nil, fmt.Errorf("the config directory %s is refused: %w", dir, err)
	}
	ad, err := osservice.OpenTrustedDir(filepath.Dir(path), trusted, false)
	if err != nil {
		_ = cd.Close()
		return nil, fmt.Errorf("the credential directory %s is refused: %w", filepath.Dir(path), err)
	}
	return &rootFiles{configDir: cd, agentsDir: ad, configName: filepath.Base(configPath), name: filepath.Base(path), trusted: trusted, self: os.Geteuid()}, nil
}

// ownerOf is path's owner, not following a link.
func ownerOf(path string) (int, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read the directory's owner")
	}
	return int(st.Uid), nil
}

func (r *rootFiles) readCredential() (string, error) {
	dsn, _, err := r.read(r.name, 0)
	return dsn, err
}

func (r *rootFiles) ReadPending(limit int) (string, os.FileInfo, error) {
	return r.read(r.name+handoff.PendingSuffix, limit)
}

// read reads the credential file name in agents/ (config.ReadCredentialAt:
// root's or the owner of agents/'s), of at most limit bytes, or for limit 0
// config's own limit. Root connects with what it reads, and pgx reads files
// for the caller from some parameters, so a file the owner of agents/ wrote
// must pass pgdial.CheckForeignDSN, as basalt init --remote's read as root
// does.
func (r *rootFiles) read(name string, limit int) (string, os.FileInfo, error) {
	var (
		dsn string
		fi  os.FileInfo
		err error
	)
	if limit > 0 {
		dsn, fi, err = config.ReadCredentialAtLimit(r.agentsDir, name, limit)
	} else {
		dsn, fi, err = config.ReadCredentialAt(r.agentsDir, name)
	}
	if err != nil {
		return "", nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || r.self < 0 || uint64(st.Uid) != uint64(r.self) {
		if err := pgdial.CheckForeignDSN(dsn); err != nil {
			return "", nil, fmt.Errorf("the credential file %s belongs to the owner of %s, not root: as root, basalt engine takes from it %w; "+
				"start the engine as its own user (as basalt service install does), or fix the file", filepath.Join(r.agentsDir.Path(), name), r.agentsDir.Path(), err)
		}
	}
	return dsn, fi, nil
}

func (r *rootFiles) Promote(pending os.FileInfo) error {
	if err := config.SameFileAt(r.agentsDir, r.name+handoff.PendingSuffix, pending); err != nil {
		return err
	}
	return r.agentsDir.Rename(r.name+handoff.PendingSuffix, r.name)
}

func (r *rootFiles) Lock() (func(), error) {
	return config.LockAt(r.agentsDir, r.name+handoff.LockSuffix)
}

func (r *rootFiles) ClearSetup(agent, id string) (bool, error) {
	owner, err := r.configDir.Owner()
	if err != nil {
		return false, err
	}
	if owner <= 0 {
		owner = -1 // root's directory: the file stays root's
	}
	return config.ClearSetupAt(r.configDir, r.configName, func(f *os.File) error { return config.CheckTrustedConfig(f, r.trusted) }, owner, agent, id)
}

func (r *rootFiles) close() {
	_ = r.agentsDir.Close()
	_ = r.configDir.Close()
}
