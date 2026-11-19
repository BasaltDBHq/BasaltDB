//go:build unix

package keptplugins

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// EntriesPath is the entries file.
func (s *Store) EntriesPath() string { return filepath.Join(s.stateDir, EntriesFile) }

// Entries reads the entries file and checks it against cfg, the engine's
// config: a missing file is no entries. A file that fails the path rule
// (a regular file with one link, the engine's user's, writable by no one
// else), is over MaxEntriesFileBytes, does not parse, or breaks a rule
// (config.Config.CheckKeptPlugins) is refused UNSAFE_PATH, its message
// naming the file and the rule, and is never overwritten.
func (s *Store) Entries(cfg config.Config) ([]config.Plugin, error) {
	raw, err := s.readEntries()
	if err != nil || raw == nil {
		return nil, err
	}
	bad := func(why string) error {
		return refused(ReasonUnsafePath, "%s %s, so the engine keeps no plugin entry until it is moved aside "+
			"(sudo mv %s %s.bad) and the engine restarted", s.EntriesPath(), why, s.EntriesPath(), s.EntriesPath())
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var entries []config.Plugin
	if err := dec.Decode(&entries); err != nil || dec.More() {
		return nil, bad("is not a JSON array of plugin entries")
	}
	if entries == nil {
		return nil, bad("is not a JSON array of plugin entries")
	}
	if err := withNamedAgents(cfg, entries).CheckKeptPlugins(entries); err != nil {
		return nil, bad("breaks a rule (" + err.Error() + ")")
	}
	return entries, nil
}

// withNamedAgents is cfg with every agent entries name: an agent removed
// from engine.json since does not make the file unusable (every method
// would then refuse it, disable and remove included). Such an agent is
// served nothing: the engine serves only its own agents. A request names
// only the engine's agents (PLUGIN_OPEN checks them on its own).
func withNamedAgents(cfg config.Config, entries []config.Plugin) config.Config {
	out := cfg
	out.Agents = slices.Clone(cfg.Agents)
	for _, p := range entries {
		for _, a := range p.Agents {
			if !out.HasAgent(a) {
				out.Agents = append(out.Agents, config.Agent{Name: a})
			}
		}
	}
	return out
}

// readEntries reads the entries file's bytes, nil when it does not exist.
func (s *Store) readEntries() ([]byte, error) {
	p := s.EntriesPath()
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	unsafe := func(why string) error {
		return refused(ReasonUnsafePath, "%s %s, so the engine keeps no plugin entry until it is moved aside "+
			"(sudo mv %s %s.bad) and the engine restarted", p, why, p, p)
	}
	if err != nil {
		return nil, unsafe("cannot be opened, or is a symlink")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, unsafe("cannot be read")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, unsafe("is not a regular file")
	case !ok || st.Nlink != 1:
		return nil, unsafe("has more than one link")
	case st.Uid != uint32(os.Geteuid()):
		return nil, unsafe("is " + errNotEngineUser.Error())
	case fi.Mode().Perm()&0o022 != 0:
		return nil, unsafe("can be written by group or others")
	case fi.Size() > MaxEntriesFileBytes:
		return nil, unsafe(fmt.Sprintf("is over %d bytes", MaxEntriesFileBytes))
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxEntriesFileBytes+1))
	if err != nil {
		return nil, unsafe("cannot be read")
	}
	if len(raw) > MaxEntriesFileBytes {
		return nil, unsafe(fmt.Sprintf("is over %d bytes", MaxEntriesFileBytes))
	}
	return raw, nil
}

// Update applies change to the entries under an exclusive lock on
// plugins.json.lock and writes the result whole, as a new file renamed into
// place (mode 0600). An entries file that cannot be used is never
// overwritten (UNSAFE_PATH). change returns the entries to write; an error
// from it writes nothing.
func (s *Store) Update(cfg config.Config, change func([]config.Plugin) ([]config.Plugin, error)) error {
	release, err := config.LockFile(filepath.Join(s.stateDir, lockFile))
	if err != nil {
		return refused(ReasonUnsafePath, "the lock %s cannot be taken: %s", filepath.Join(s.stateDir, lockFile), err)
	}
	defer release()
	entries, err := s.Entries(cfg)
	if err != nil {
		return err
	}
	next, err := change(slices.Clone(entries))
	if err != nil {
		return err
	}
	if next == nil {
		next = []config.Plugin{}
	}
	if err := withNamedAgents(cfg, next).CheckKeptPlugins(next); err != nil {
		return fmt.Errorf("the engine-kept entries would break a rule: %w", err)
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.stateDir, EntriesFile, append(raw, '\n'))
}

// writeAtomic writes name in dir whole: a new temporary file, synced, then
// renamed into place, mode 0600.
func writeAtomic(dir, name string, raw []byte) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(privateFile); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	ok = true
	return nil
}

// Stage checks the taken upload as a copy of entry (name, instance): it
// holds the manifest, its signature or none, and exactly the files the
// manifest lists (BAD_MANIFEST otherwise); executables are files the
// manifest lists; then plugin.Stage copies and verifies it under Root with
// plugin.RequireApproval, as a same-user install of an entry that requires
// approval. The staged copy is not in place until Commit.
func (s *Store) Stage(t *Taken, name, instance string, executables []string) (*plugin.Staged, error) {
	manifest, err := t.Manifest()
	if err != nil {
		return nil, err
	}
	m, err := plugin.ParseManifest(manifest)
	if err != nil {
		return nil, refusalOf(err)
	}
	if m.Name != name {
		return nil, refused(ReasonBadManifest, "the manifest names the plugin %q, not %q", m.Name, name)
	}
	for _, p := range t.Paths {
		if p == plugin.ManifestFile || p == plugin.SignatureFile {
			continue
		}
		if _, ok := m.Files[p]; !ok {
			return nil, refused(ReasonBadManifest, "the upload holds %s, which the manifest does not list in files", p)
		}
	}
	for p := range m.Files {
		if !slices.Contains(t.Paths, p) {
			return nil, refused(ReasonBadManifest, "the manifest lists %s, which the upload does not hold", p)
		}
	}
	for _, p := range executables {
		if _, ok := m.Files[p]; !ok {
			return nil, refused(ReasonBadManifest, "executables names %s, which the manifest does not list in files", p)
		}
	}
	if err := t.MarkExecutables(executables); err != nil {
		return nil, err
	}
	trust, err := s.Trust()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Root(), copiesDirMode); err != nil {
		return nil, refused(ReasonUnsafePath, "%s cannot be made", s.Root())
	}
	st, err := plugin.Stage(t.Dir, s.Root(), instance, trust, plugin.ModeSameUser, plugin.RequireApproval(true))
	if err != nil {
		return nil, refusalOf(err)
	}
	return st, nil
}

// Manifest reads the upload's manifest: inside the upload only, never
// through a link, a regular file of at most plugin.MaxManifestBytes.
func (t *Taken) Manifest() ([]byte, error) {
	if !slices.Contains(t.Paths, plugin.ManifestFile) {
		return nil, refused(ReasonBadManifest, "the upload holds no %s", plugin.ManifestFile)
	}
	root, err := os.OpenRoot(t.Dir)
	if err != nil {
		return nil, refused(ReasonUnsafePath, "the upload's directory cannot be opened")
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(plugin.ManifestFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refused(ReasonUnsafePath, "%s of the upload cannot be opened, or is a symlink", plugin.ManifestFile)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, refused(ReasonUnsafePath, "%s of the upload is not a regular file", plugin.ManifestFile)
	}
	raw, err := io.ReadAll(io.LimitReader(f, plugin.MaxManifestBytes+1))
	if err != nil || len(raw) > plugin.MaxManifestBytes {
		return nil, refused(ReasonTooLarge, "%s of the upload is over %d bytes", plugin.ManifestFile, plugin.MaxManifestBytes)
	}
	return raw, nil
}

// Commit puts a staged copy in place and recounts the storage.
func (s *Store) Commit(st *plugin.Staged) (plugin.Verified, error) {
	dir, err := st.Commit()
	if err != nil {
		return plugin.Verified{}, refusalOf(err)
	}
	s.recountCopies()
	v := st.Verified
	v.Dir = dir
	return v, nil
}

// Verify checks the installed copy of an engine-kept entry, as the engine
// does before it serves or starts one.
func (s *Store) Verify(k plugin.EntryKey, manifestSHA256 string) (plugin.Verified, error) {
	trust, err := s.Trust()
	if err != nil {
		return plugin.Verified{}, err
	}
	return plugin.Verify(s.Root(), k, manifestSHA256, trust, plugin.ModeSameUser, plugin.RequireApproval(true))
}

// Tidy removes entry k's instance and name directories when they hold
// nothing: what a refused staging leaves.
func (s *Store) Tidy(k plugin.EntryKey) {
	inst := filepath.Join(s.Root(), k.Name, k.Instance)
	if filepath.Dir(filepath.Dir(inst)) != s.Root() {
		return
	}
	_ = os.Remove(inst)
	_ = os.Remove(filepath.Dir(inst))
}

// RemoveCopies removes entry k's copies but keep ("" removes every one),
// and recounts the storage.
func (s *Store) RemoveCopies(k plugin.EntryKey, keep string) error {
	err := plugin.Sweep(s.Root(), k, keep, plugin.ModeSameUser)
	s.recountCopies()
	return err
}

// Sweep removes every copy under Root that no entry of entries names (a
// crash between writing a copy and its entry), and recounts the storage.
func (s *Store) Sweep(entries []config.Plugin) {
	names, err := os.ReadDir(s.Root())
	if err != nil {
		return
	}
	keep := map[plugin.EntryKey]string{}
	for _, p := range entries {
		keep[p.Key()] = p.ManifestSHA256
	}
	for _, n := range names {
		insts, err := os.ReadDir(filepath.Join(s.Root(), n.Name()))
		if err != nil {
			continue
		}
		for _, i := range insts {
			k := plugin.EntryKey{Name: n.Name(), Instance: i.Name()}
			sha, ok := keep[k]
			if !ok {
				sha = ""
			}
			_ = plugin.Sweep(s.Root(), k, sha, plugin.ModeSameUser)
		}
	}
	s.recountCopies()
}

// refusalOf maps a verification failure to its PLUGIN_REFUSED reason:
// BAD_MANIFEST, UNSAFE_PATH for the path rule, NOT_TRUSTED otherwise.
func refusalOf(err error) error {
	var ve *plugin.VerifyError
	if !errors.As(err, &ve) {
		return err
	}
	reason := string(ve.Reason)
	if ve.Path != nil {
		reason = ReasonUnsafePath
	}
	return &Error{Kind: KindRefused, Reason: reason, Message: "the plugin is refused: " + ve.Error() + ". Nothing was written"}
}
