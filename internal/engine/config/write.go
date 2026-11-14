package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

const (
	// FileMode is the mode of the config and credential files: the engine's
	// user only.
	FileMode = 0o600
	dirMode  = 0o700
)

// Settings are what basalt init writes besides the agent.
type Settings struct {
	// SocketDir and StateDir are used only when the config file is new.
	SocketDir, StateDir string
	// PagesURL replaces the config's pages base URL when set, and
	// DevLocalPages replaces devLocalPages along with it: the development
	// exception goes with the pages it is for.
	PagesURL      string
	DevLocalPages bool
	// OperatedBy replaces the config's operatedBy when set.
	OperatedBy string
	// Mode replaces the config's mode when set.
	Mode Mode
	// PersonUIDs are added to the config's person uids; the recorded ones
	// stay (re-running init keeps them).
	PersonUIDs []uint32
	// Vault replaces the config's vault (VaultOn or VaultOff) when set:
	// the person chose it (--vault).
	Vault string
	// VaultDefault is the vault written when Vault is empty and the config
	// has none yet, or when OperatedBy changes the config's operatedBy.
	// Otherwise the config's vault stays: a rerun never undoes the
	// person's choice (VC-19).
	VaultDefault string
}

// operatedByPerson is operatedBy's value when empty.
const operatedByPerson = "PERSON"

// VaultWritten is the vault an upsert wrote, and whether it is the one
// the config already had (neither chosen nor the default applied).
type VaultWritten struct {
	Vault string
	Kept  bool
}

// vaultFor is the vault s writes over the existing config prev (existed
// false: no file yet).
func (s Settings) vaultFor(prev Config, existed bool) VaultWritten {
	switch {
	case s.Vault != "":
		return VaultWritten{Vault: s.Vault}
	case existed && prev.Vault != "" && !s.changesOperatedBy(prev):
		return VaultWritten{Vault: prev.Vault, Kept: true}
	case s.VaultDefault != "":
		return VaultWritten{Vault: s.VaultDefault}
	}
	return VaultWritten{Vault: prev.Vault, Kept: prev.Vault != ""}
}

// changesOperatedBy reports whether s sets an operatedBy other than
// prev's (empty is PERSON).
func (s Settings) changesOperatedBy(prev Config) bool {
	if s.OperatedBy == "" {
		return false
	}
	was := prev.OperatedBy
	if was == "" {
		was = operatedByPerson
	}
	return was != s.OperatedBy
}

// UpsertAgent adds agent a to the config at path, or replaces the agent of
// the same name, creating the file from s when it does not exist. basalt
// init calls it. The file is written atomically with FileMode.
func UpsertAgent(path string, s Settings, a Agent) error {
	_, err := UpsertAgentVault(path, s, a)
	return err
}

// UpsertAgentVault is UpsertAgent, returning the vault it wrote. It holds
// the config's lock (lockConfig) from the read to the write, so a setup the
// engine clears meanwhile is not lost, nor this agent by the engine's write.
func UpsertAgentVault(path string, s Settings, a Agent) (VaultWritten, error) {
	unlock, err := lockConfig(path)
	if err != nil {
		return VaultWritten{}, err
	}
	defer unlock()
	raw, v, err := UpsertedVault(path, openNoFollow, s, a)
	if err != nil {
		return VaultWritten{}, err
	}
	return v, WriteFile(path, raw)
}

// Upserted is the content UpsertAgent writes, without writing it: the
// service install writes it itself, owned by the engine's OS user.
func Upserted(path string, s Settings, a Agent) ([]byte, error) {
	return UpsertedWith(path, openNoFollow, s, a)
}

// UpsertedWith is Upserted reading the existing file through open. The
// service install, as root, passes one that follows no link anywhere on the
// path and accepts only a file the engine's user owns.
func UpsertedWith(path string, open func(string) (*os.File, error), s Settings, a Agent) ([]byte, error) {
	raw, _, err := UpsertedVault(path, open, s, a)
	return raw, err
}

// UpsertedVault is UpsertedWith, returning the vault it wrote.
func UpsertedVault(path string, open func(string) (*os.File, error), s Settings, a Agent) ([]byte, VaultWritten, error) {
	c, err := load(path, open)
	existed := true
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c, existed = Config{SocketDir: s.SocketDir, StateDir: s.StateDir}, false
	case err != nil:
		return nil, VaultWritten{}, err
	}
	vault := s.vaultFor(c, existed)
	c.Vault = vault.Vault
	if s.PagesURL != "" {
		c.PagesURL, c.ApprovalPage, c.DevLocalPages = s.PagesURL, "", s.DevLocalPages
	}
	if s.OperatedBy != "" {
		c.OperatedBy = s.OperatedBy
	}
	if s.Mode != "" {
		c.Mode = s.Mode
	}
	c.PersonUIDs = addUIDs(c.PersonUIDs, s.PersonUIDs)
	replaced := false
	for i := range c.Agents {
		if c.Agents[i].Name == a.Name {
			c.Agents[i], replaced = a, true
		}
	}
	if !replaced {
		c.Agents = append(c.Agents, a)
	}
	if err := validate.Struct(c); err != nil {
		return nil, VaultWritten{}, fmt.Errorf("config %s: %w", path, err)
	}
	// Never write a config the engine would refuse to load.
	if err := c.checkOrigins(); err != nil {
		return nil, VaultWritten{}, fmt.Errorf("config %s: %w", path, err)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, VaultWritten{}, err
	}
	return append(raw, '\n'), vault, nil
}

// ClearSetup removes agent's pending setup from the config at path, once
// the engine found it recorded (CONTRACT.md, Setup from your laptop, On the
// engine). Only setup id is cleared: when the agent's pending setup is
// another one (basalt init --remote made a new code meanwhile) or none,
// the file is left as it is and cleared is false. The file is read without
// following a link and written atomically with FileMode, under the config's
// lock (lockConfig), which every upsert takes too, so a change to another
// agent made meanwhile is never lost. The caller also holds the agent's lock
// (LockFile), as basalt init --remote does.
func ClearSetup(path, agent, id string) (cleared bool, err error) {
	unlock, err := lockConfig(path)
	if err != nil {
		return false, err
	}
	defer unlock()
	c, err := load(path, openNoFollow)
	if err != nil {
		return false, err
	}
	i := slices.IndexFunc(c.Agents, func(a Agent) bool { return a.Name == agent })
	if i < 0 || c.Agents[i].Setup == nil || c.Agents[i].Setup.SetupID != id {
		return false, nil
	}
	c.Agents[i].Setup = nil
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return false, err
	}
	return true, WriteFile(path, append(raw, '\n'))
}

// WriteFile writes data to path atomically with FileMode, creating the
// directory (mode 0700) when missing. It writes a new temporary file
// (O_EXCL, so never through a planted link) and renames it over path,
// which replaces a link rather than following it; a path that is a
// symlink or not a regular file is refused all the same, since nothing
// basalt writes is ever one.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (a symlink?); refusing to write it", path)
	}
	tmp, err := os.CreateTemp(dir, ".basalt-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// addUIDs is have with every uid of add it lacks, in order.
func addUIDs(have, add []uint32) []uint32 {
	for _, u := range add {
		if !slices.Contains(have, u) {
			have = append(have, u)
		}
	}
	return have
}
