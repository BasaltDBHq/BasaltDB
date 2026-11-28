//go:build unix

package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/handofffiles"
)

// The files the engine itself writes in its state and socket folders. Only
// these are deleted outside the default config folder; a folder is then
// removed only when it is empty.
var (
	stateFiles = []string{
		channel.KeyFileName, pii.KeyFileName, pii.DictionaryFileName, pii.StatusFileName,
		handofffiles.ProbeCacheName, engine.LastStopFile, "engine.log", "start.lock",
		"update-check.json", "portal-check.json", "plugins.json",
	}
	stateSuffixes = []string{".head.json"}
	socketFiles   = []string{"engine.lock", "start.lock", engine.SuperviseLock}
	socketSuffix  = []string{".sock"}
)

// removeEngineFiles deletes what an agent-operated engine keeps on the
// bot's machine (CONTRACT.md, Connect, The removal hand-off), never as
// root and never through a link. cfg is engine.json as read just before.
func removeEngineFiles(cfg config.Config, configPath, agent string) error {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	return removeEngineFilesIn(cfg, configPath, agent, config.UserPath(base))
}

// removeEngineFilesIn is removeEngineFiles with the default config path
// given:
//
//   - a config at exactly that path has its whole folder removed
//     (<UserConfigDir>/basalt: engine.json, agents/, trust.d, and the state
//     and socket folders, which are inside it by default);
//   - otherwise only engine.json, its lock and the agent's credential files
//     at the path basalt init writes them (agents/<agent>.url next to the
//     config, with .pending, .lock and .secret) are removed;
//   - a state or socket folder outside the removed folder loses only the
//     files the engine writes there, and is removed only when it is then
//     empty;
//   - a credential file elsewhere was not written by basalt, so it stays
//     (errCredentialKept).
//
// The basalt binary stays. Every failure is returned after the rest ran.
func removeEngineFilesIn(cfg config.Config, configPath, agent, defaultPath string) error {
	if os.Geteuid() == 0 {
		return errors.New("an engine started as root never removes itself")
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := ownDir(dir); err != nil {
		return err
	}
	ownFolder := abs == filepath.Clean(defaultPath)
	gone := func(p string) bool { return ownFolder && inside(dir, p) }
	var errs []error
	agentsDir := filepath.Join(dir, "agents")
	written := filepath.Join(agentsDir, agent+".url")
	for _, a := range cfg.Agents {
		if a.Name != agent {
			continue
		}
		cred := a.Store.CredentialFile
		if !filepath.IsAbs(cred) {
			cred = filepath.Join(dir, cred)
		}
		if filepath.Clean(cred) != written && !gone(cred) {
			errs = append(errs, fmt.Errorf("%s: %w", cred, errCredentialKept))
		}
	}
	if !ownFolder {
		for _, p := range []string{written, written + config.PendingSuffix, written + config.LockSuffix, filepath.Join(agentsDir, agent+config.SecretSuffix)} {
			errs = append(errs, removePlain(p))
		}
		errs = append(errs, removeIfEmpty(agentsDir))
	}
	errs = append(errs,
		emptyFolder(cfg.StateDirFor(runtime.GOOS), stateFiles, stateSuffixes, gone),
		emptyFolder(cfg.SocketDir, socketFiles, socketSuffix, gone))
	if ownFolder {
		errs = append(errs, os.RemoveAll(dir))
	} else {
		errs = append(errs, removePlain(abs), removePlain(abs+config.LockSuffix))
	}
	return errors.Join(errs...)
}

// emptyFolder deletes, in folder d of this user, the files named in names
// or ending in one of suffixes, and the crash folder's files, then removes
// d when it is empty. A folder that goes with the config folder (gone) is
// left to that; one that is missing is nothing to do. A folder that is not
// empty afterwards stays and is an error.
func emptyFolder(d string, names, suffixes []string, gone func(string) bool) error {
	if d == "" || gone(d) {
		return nil
	}
	if err := ownDir(d); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		switch {
		case name == servicespec.CrashDirName && e.IsDir():
			errs = append(errs, emptyFolder(filepath.Join(d, name), nil, []string{""}, func(string) bool { return false }))
		case matches(name, names, suffixes):
			errs = append(errs, removeOwn(filepath.Join(d, name)))
		}
	}
	errs = append(errs, removeIfEmpty(d))
	return errors.Join(errs...)
}

func matches(name string, names, suffixes []string) bool {
	for _, n := range names {
		if name == n {
			return true
		}
	}
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// removeIfEmpty removes folder d when it is empty; a folder with anything
// left in it stays and is an error.
func removeIfEmpty(d string) error {
	entries, err := os.ReadDir(d)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s still holds files that are not the engine's, so it stays", d)
	}
	return os.Remove(d)
}

// inside reports whether p is dir or below it.
func inside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ownDir is nil when path is a folder of this user, not a link.
func ownDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not a folder of this user, so it stays", path)
	}
	return nil
}

// removeOwn removes path when it is this user's and not a folder: a plain
// file or a socket, never a link's target (Remove unlinks a link itself).
func removeOwn(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not a file of this user, so it stays", path)
	}
	return os.Remove(path)
}

// removePlain removes path when it is a plain file of this user with one
// link; a missing file is nothing to do, and any other file stays
// (errCredentialKept).
func removePlain(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return fmt.Errorf("%s: %w", path, errCredentialKept)
	}
	return os.Remove(path)
}
