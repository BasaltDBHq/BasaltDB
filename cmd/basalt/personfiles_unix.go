//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	service "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/config"
)

// loadConfigAsRoot reads the engine config for a root person CLI (sudo
// basalt log, approve, revert, status, upgrade and access, which
// open the agent's ledger through openLedger, the config reads behind
// log's dictionary line, access's commands and the pages links, and init
// --remote: every person-CLI root path reads the config here, which
// TestNoRootPathUsesPlainConfigLoad guards). The config's directory
// may belong to the engine's user, who could plant a link there, so the
// file is reached from / without following one (service.OpenTrustedFile,
// with the directory's owner as the trusted user) and must be a regular
// file with one link owned by root or that user, not writable by group or
// others. trusted is that user: the
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

// checkConfigFile checks the opened config before it is read: a plain
// file, owned by root or trusted, not writable by group or others.
func checkConfigFile(f *os.File, trusted int) error {
	return config.CheckTrustedConfig(f, trusted)
}

// readCredentialAsRoot reads an agent's credential for a root person CLI:
// reached without following a link, a regular file with one link, mode
// 0600 or tighter, owned by trusted (readOwnedCredential). trusted is the
// config's (loadConfigAsRoot), or, for --credential-file, the owner of
// the file's directory. Root connects with what it reads, and pgx reads
// files for the caller from some parameters, so a file another user owns
// (trusted is not root) must pass pgdial.CheckForeignDSN, as root's init
// --remote and root engine reads do.
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
	if trusted != 0 {
		if err := pgdial.CheckForeignDSN(line); err != nil {
			return "", fmt.Errorf("credential file %s belongs to uid %d, not root: as root, basalt takes from it %w; "+
				"run the command as that user (sudo -u <user>), or fix the file", path, trusted, err)
		}
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
