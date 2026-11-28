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
)

// removeEngineFiles deletes what an agent-operated engine keeps on the
// bot's machine (CONTRACT.md, Connect, The removal hand-off), never as
// root and never through a link:
//
//   - its config folder, <UserConfigDir>/basalt with engine.json, agents/,
//     trust.d and, by default, the state and socket folders, when the
//     config is that default one; with a config elsewhere, only engine.json
//     and its lock, since that folder is not the engine's own;
//   - its state and socket folders outside it, when they are folders of
//     this user;
//   - the agent's credential file and the files init keeps next to it
//     (.pending, .lock, .secret) outside the config folder, when each is a
//     plain file of this user with one link. Another file stays
//     (errCredentialKept).
//
// The basalt binary stays. Every failure is returned after the rest ran.
func removeEngineFiles(cfg config.Config, configPath, agent string) error {
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
	ownFolder := filepath.Base(dir) == config.UserDirName
	var errs []error
	for _, a := range cfg.Agents {
		if a.Name != agent {
			continue
		}
		cred := a.Store.CredentialFile
		if !filepath.IsAbs(cred) {
			cred = filepath.Join(dir, cred)
		}
		for _, p := range []string{cred, cred + config.PendingSuffix, cred + config.LockSuffix, strings.TrimSuffix(cred, filepath.Ext(cred)) + config.SecretSuffix} {
			if ownFolder && inside(dir, p) {
				continue
			}
			errs = append(errs, removePlain(p))
		}
	}
	for _, d := range []string{cfg.StateDirFor(runtime.GOOS), cfg.SocketDir} {
		if d == "" || (ownFolder && inside(dir, d)) {
			continue
		}
		if err := ownDir(d); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		errs = append(errs, os.RemoveAll(d))
	}
	if ownFolder {
		errs = append(errs, os.RemoveAll(dir))
	} else {
		errs = append(errs, removePlain(abs), removePlain(abs+config.LockSuffix))
	}
	return errors.Join(errs...)
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
