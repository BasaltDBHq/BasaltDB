//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// loadConfigAsRoot reads the engine config for a root person CLI (sudo
// basalt log, approve, revert, status, upgrade, access and classify, which
// open the agent's ledger through openLedger, and the config reads behind
// log's dictionary line, access's commands and the pages links: every root
// path reads the config here). The config's directory
// may belong to the engine's user, who could plant a link there, so the
// file is reached from / without following one (service.OpenTrustedFile,
// with the directory's owner as the trusted user) and must be a regular
// file with one link owned by root or that user. trusted is that user: the
// credential the config names must belong to it (readCredentialAsRoot),
// so a config the engine's user wrote cannot name a file only root reads.
func loadConfigAsRoot(path string) (cfg config.Config, trusted int, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return config.Config{}, 0, err
	}
	trusted, err = dirOwner(abs)
	if err != nil {
		return config.Config{}, 0, err
	}
	cfg, err = config.LoadOpen(abs, func(p string) (*os.File, error) {
		f, err := service.OpenTrustedFile(p, trusted)
		if err != nil {
			return nil, err
		}
		if err := checkConfigFile(f, trusted); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	})
	return cfg, trusted, err
}

func checkConfigFile(f *os.File, trusted int) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := config.CheckPlainFile(fi); err != nil {
		return fmt.Errorf("%s: %w", f.Name(), err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file's owner")
	}
	if uid := int(st.Uid); uid != 0 && uid != trusted {
		return fmt.Errorf("%s is owned by uid %d, not root or uid %d (its directory's owner)", f.Name(), uid, trusted)
	}
	return nil
}

// readCredentialAsRoot reads an agent's credential for a root person CLI:
// reached without following a link, a regular file with one link, mode
// 0600 or tighter, owned by trusted (readOwnedCredential). trusted is the
// config's (loadConfigAsRoot), or, for --credential-file, the owner of
// the file's directory.
func readCredentialAsRoot(path string, trusted int, fromConfig bool) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !fromConfig {
		if trusted, err = dirOwner(abs); err != nil {
			return "", err
		}
	}
	line, err := readOwnedCredential(abs, trusted, fmt.Sprintf("uid %d", trusted))
	if err != nil {
		return "", fmt.Errorf("credential file %s is refused: %w", path, err)
	}
	return line, nil
}

// dirOwner is the owner of path's directory, not following a link.
func dirOwner(path string) (int, error) {
	fi, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read the directory's owner")
	}
	return int(st.Uid), nil
}
