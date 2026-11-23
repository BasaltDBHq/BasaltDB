//go:build unix

package cli

import (
	"os"
	"path/filepath"

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
// others. trusted is that user.
func loadConfigAsRoot(sh Host, path string) (cfg config.Config, trusted int, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return config.Config{}, 0, err
	}
	trusted, err = DirOwner(abs)
	if err != nil {
		return config.Config{}, 0, err
	}
	cfg, err = config.LoadOpen(abs, func(p string) (*os.File, error) {
		f, err := sh.OSOpenTrustedFile(p, trusted)
		if err != nil {
			return nil, err
		}
		if err := CheckConfigFile(f, trusted); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	})
	return cfg, trusted, err
}
