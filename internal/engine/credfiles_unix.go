//go:build unix

package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// rootFiles reaches the files of an engine started as root without --user
// (CONTRACT.md, basalt engine). The config's directory may belong to
// another user, who could swap it or agents/ for a symlink to send root's
// reads and writes elsewhere, so both directories are opened once, from /
// without following a link anyone but root controls (service.TrustedDir:
// every directory on the way owned by root or the config directory's owner,
// not writable by group or others), and every file is then reached
// relative to them, for the engine's lifetime.
type rootFiles struct {
	configDir, agentsDir *service.TrustedDir
	configName, name     string
	// trusted is the config directory's owner: the config must be owned
	// by root or that user (config.CheckTrustedConfig).
	trusted int
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
	cd, err := service.OpenTrustedDir(dir, trusted, false)
	if err != nil {
		return nil, fmt.Errorf("the config directory %s is refused: %w", dir, err)
	}
	ad, err := service.OpenTrustedDir(filepath.Dir(path), trusted, false)
	if err != nil {
		_ = cd.Close()
		return nil, fmt.Errorf("the credential directory %s is refused: %w", filepath.Dir(path), err)
	}
	return &rootFiles{configDir: cd, agentsDir: ad, configName: filepath.Base(configPath), name: filepath.Base(path), trusted: trusted}, nil
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
	dsn, _, err := config.ReadCredentialAt(r.agentsDir, r.name)
	return dsn, err
}

func (r *rootFiles) readPending() (string, os.FileInfo, error) {
	return config.ReadCredentialAt(r.agentsDir, r.name+pendingSuffix)
}

func (r *rootFiles) promote(pending os.FileInfo) error {
	if err := config.SameFileAt(r.agentsDir, r.name+pendingSuffix, pending); err != nil {
		return err
	}
	return r.agentsDir.Rename(r.name+pendingSuffix, r.name)
}

func (r *rootFiles) lock() (func(), error) { return config.LockAt(r.agentsDir, r.name+lockSuffix) }

func (r *rootFiles) clearSetup(agent, id string) (bool, error) {
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
