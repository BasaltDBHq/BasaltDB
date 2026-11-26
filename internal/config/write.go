package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
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
	// KeepConnectOnlySetup keeps the replaced agent's pending connect-only
	// setup in the new entry (basalt service install --agent for an agent
	// that waits for its database's address).
	KeepConnectOnlySetup bool
}

// operatedByPerson is operatedBy's value when empty.
const operatedByPerson = "PERSON"

// VaultWritten is the vault an upsert wrote, and whether it is the one
// the config already had (neither chosen nor the default applied).
type VaultWritten struct {
	Vault string
	Kept  bool
}

// VaultFor is the vault s writes over the existing config prev (existed
// false: no file yet).
func (s Settings) VaultFor(prev Config, existed bool) VaultWritten {
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

// UpsertAgentVault is UpsertAgent, returning the vault it wrote. It holds
// the config's lock (lockConfig) from the read to the write, so a setup the
// engine clears meanwhile is not lost, nor this agent by the engine's write.
func UpsertAgentVault(path string, s Settings, a Agent) (VaultWritten, error) {
	return upsertWith(pathFile(path), s, a)
}

// UpsertAgentVaultAt is UpsertAgentVault for a root process on the config
// file name in d, a directory it opened without following a link the
// engine's user controls (service.TrustedDir): the lock, the read and the
// write are all relative to d, so swapping the config directory for a
// symlink meanwhile redirects nothing. check vets the opened config before
// it is read (owner and mode); the file is written owned by owner (this
// process when < 0).
func UpsertAgentVaultAt(d Dir, name string, check func(*os.File) error, owner int, s Settings, a Agent) (VaultWritten, error) {
	return upsertWith(dirFile{d: d, name: name, check: check, owner: owner}, s, a)
}

// upsertWith is UpsertAgentVault on f, under f's config lock.
func upsertWith(f configFile, s Settings, a Agent) (VaultWritten, error) {
	unlock, err := f.lock()
	if err != nil {
		return VaultWritten{}, err
	}
	defer unlock()
	raw, v, err := UpsertedVault(f.path(), f.open, s, a)
	if err != nil {
		return VaultWritten{}, err
	}
	return v, f.write(raw)
}

// Dir is a directory a root process opened once, from / without following
// a link anyone but root controls (service.TrustedDir); its files are
// reached relative to the open descriptor, never by path.
type Dir interface {
	Path() string
	// Owner is the directory's owner, read through its descriptor.
	Owner() (int, error)
	// OpenFile opens name in the directory, never following a symlink.
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	// WriteFile replaces name atomically, owned by owner (< 0: this
	// process).
	WriteFile(name string, data []byte, mode os.FileMode, owner int) error
	// Rename renames from over to, both in the directory.
	Rename(from, to string) error
}

// configFile is the engine config a read-modify-write reaches: by path, or
// in a Dir.
type configFile interface {
	path() string
	lock() (func(), error)
	open(string) (*os.File, error)
	write([]byte) error
}

// pathFile is the config at a path: openNoFollow, config.WriteFile.
type pathFile string

func (p pathFile) path() string                  { return string(p) }
func (p pathFile) lock() (func(), error)         { return lockConfig(string(p)) }
func (p pathFile) open(string) (*os.File, error) { return openNoFollow(string(p)) }
func (p pathFile) write(raw []byte) error        { return WriteFile(string(p), raw) }

// dirFile is the config file name in d (UpsertAgentVaultAt).
type dirFile struct {
	d     Dir
	name  string
	check func(*os.File) error
	owner int
}

func (f dirFile) path() string { return filepath.Join(f.d.Path(), f.name) }
func (f dirFile) lock() (func(), error) {
	return waitLock(func() (func(), error) { return LockAt(f.d, f.name+".lock") })
}

func (f dirFile) open(string) (*os.File, error) {
	return OpenPlainAt(f.d, f.name, f.check)
}
func (f dirFile) write(raw []byte) error { return f.d.WriteFile(f.name, raw, FileMode, f.owner) }

// UpsertedVault is the content UpsertAgentVault writes, without writing it,
// reading the existing file through open, and the vault it wrote. The root
// service install passes an open that follows no link anywhere on the path
// and accepts only a file the engine's user owns.
func UpsertedVault(path string, open func(string) (*os.File, error), s Settings, a Agent) ([]byte, VaultWritten, error) {
	c, err := load(path, open)
	existed := true
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c, existed = Config{SocketDir: s.SocketDir, StateDir: s.StateDir}, false
	case err != nil:
		return nil, VaultWritten{}, err
	}
	vault := s.VaultFor(c, existed)
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
			if prev := c.Agents[i].Setup; s.KeepConnectOnlySetup && a.Setup == nil && prev != nil && prev.ConnectOnly() {
				a.Setup = prev
			}
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
// the engine found it recorded (CONTRACT.md, Setup, On the
// engine). Only setup id is cleared: when the agent's pending setup is
// another one (basalt init --remote made a new code meanwhile) or none,
// the file is left as it is and cleared is false. The file is read without
// following a link and written atomically with FileMode, under the config's
// lock (lockConfig), which every upsert takes too, so a change to another
// agent made meanwhile is never lost. The caller also holds the agent's lock
// (LockFile), as basalt init --remote does.
func ClearSetup(path, agent, id string) (cleared bool, err error) {
	return clearSetupWith(pathFile(path), agent, id)
}

// ClearSetupAt is ClearSetup for a root process on the config file name in
// d (see UpsertAgentVaultAt).
func ClearSetupAt(d Dir, name string, check func(*os.File) error, owner int, agent, id string) (bool, error) {
	return clearSetupWith(dirFile{d: d, name: name, check: check, owner: owner}, agent, id)
}

func clearSetupWith(f configFile, agent, id string) (cleared bool, err error) {
	unlock, err := f.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	c, err := load(f.path(), f.open)
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
	return true, f.write(append(raw, '\n'))
}

// Change is one read-modify-write of the config (UpdateConfig).
type Change struct {
	// Apply changes the config read under the lock; an error leaves the file
	// as it was.
	Apply func(*Config) error
	// Written, when set, runs after the file is written, still under the
	// lock, with the config written.
	Written func(Config)
}

// UpdateConfig changes the existing config at path: under the config's
// lock (lockConfig) it reads the file without following a link, applies
// ch, checks the result as Load would, and writes it atomically with
// FileMode. When Apply or the check fails, the file is left as it was.
// basalt plugin writes its entries this way.
func UpdateConfig(path string, ch Change) error {
	return updateWith(pathFile(path), ch)
}

func updateWith(f configFile, ch Change) error {
	unlock, err := f.lock()
	if err != nil {
		return err
	}
	defer unlock()
	c, err := load(f.path(), f.open)
	if err != nil {
		return err
	}
	if err := ch.Apply(&c); err != nil {
		return err
	}
	// Never write a config the engine would refuse to load.
	if err := c.check(); err != nil {
		return fmt.Errorf("config %s: %w", f.path(), err)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := f.write(append(raw, '\n')); err != nil {
		return err
	}
	if ch.Written != nil {
		ch.Written(c)
	}
	return nil
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
	return atomicfile.Write(path, data, atomicfile.Options{Mode: FileMode, RefuseNonRegular: true})
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

// RemoveAgents removes the agents names from the config at path, and from
// every plugin entry's agents, under the config's lock (lockConfig). When no agent is left, it removes the file
// whole: a config needs one agent, and an engine with no config waits for
// a first install. It returns whether it removed the file. A name the
// config does not have is skipped.
func RemoveAgents(path string, names []string) (removedFile bool, err error) {
	f := pathFile(path)
	unlock, err := f.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	c, err := load(f.path(), f.open)
	if err != nil {
		return false, err
	}
	c.Agents = slices.DeleteFunc(c.Agents, func(a Agent) bool { return slices.Contains(names, a.Name) })
	// A plugin entry names the agents it serves; it keeps serving the
	// others, and an empty list serves none.
	for i := range c.Plugins {
		c.Plugins[i].Agents = slices.DeleteFunc(slices.Clone(c.Plugins[i].Agents), func(a string) bool { return slices.Contains(names, a) })
	}
	if len(c.Agents) == 0 {
		return true, os.Remove(path)
	}
	if err := c.check(); err != nil {
		return false, fmt.Errorf("config %s: %w", path, err)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return false, err
	}
	return false, f.write(append(raw, '\n'))
}
