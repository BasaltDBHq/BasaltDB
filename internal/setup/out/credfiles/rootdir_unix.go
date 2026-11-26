//go:build unix

package credfiles

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// The config directory and the engine's key as root, for basalt init
// --remote: opened from / without following a link anyone but root or the
// config directory's owner controls.

// rootConfigDir is the config directory init --remote opened as root
// (service.OpenTrustedDir, the trusted owner as OpenRootCredFiles): it
// locks, reads and writes engine.json relative to it.
type rootConfigDir struct {
	dir     TrustedDir
	trusted int
}

// RootTrustedOwner is the owner root trusts on the way to the config
// directory dir: dir's, or, when it does not exist yet, that of the
// nearest directory above it that does, not following a link. Read once,
// before either directory is made.
func RootTrustedOwner(dir string) (int, error) {
	path := dir
	for {
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) && filepath.Dir(path) != path {
			path = filepath.Dir(path)
			continue
		}
		if err != nil {
			return 0, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, errors.New("cannot read the directory's owner")
		}
		return int(st.Uid), nil
	}
}

// OpenRootConfigDir opens dir, the config directory, as root, making it
// when missing, through h. trusted is RootTrustedOwner's.
func OpenRootConfigDir(h FilesHost, dir string, trusted int) (ConfigDir, error) {
	d, err := h.OSOpenTrustedDir(dir, trusted, true)
	if err != nil {
		return nil, fmt.Errorf("the config directory %s is refused: %w", dir, err)
	}
	return &rootConfigDir{dir: d, trusted: trusted}, nil
}

// Upsert is config.UpsertAgentVault on the config file name, relative to
// the opened directory, the file checked as the hardened read checks it and
// written owned by the directory's owner.
func (d *rootConfigDir) Upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error) {
	dirUID, err := d.dir.Owner()
	if err != nil {
		return config.VaultWritten{}, err
	}
	// engine.json goes to the config directory's owner (the engine's user
	// in service mode), as the files in agents/ do, so the engine can read
	// it; never to root.
	return config.UpsertAgentVaultAt(d.dir, name, func(f *os.File) error { return config.CheckTrustedConfig(f, d.trusted) }, CredentialOwner(dirUID), s, a)
}

func (d *rootConfigDir) Close() { _ = d.dir.Close() }

// RootEngineKey is the engine's public key for a root init --remote: the
// key file in the engine's state directory, read or (when there is none)
// created relative to that directory, opened from / without following a
// link anyone but root controls. stateDir comes from engine.json, which
// the config directory's owner may write, so it is trusted no further than
// the config directory: every directory on the way must be owned by root
// or that owner (cfg.trusted), the state directory itself by the config
// directory's owner, and it is never made here (the service manager makes
// it when the service starts). The file must be a regular file with one
// link, owned by that owner, mode 0600 or narrower, and pass the engine's
// own checks (channel.ParseKeyFile). A new one is given to that owner
// before it appears under its name, so the engine loads it as its own; one
// made meanwhile by the engine is kept. The directory is opened through h;
// cfg is the one OpenRootConfigDir opened, and stateDirMode is the
// engine's mode for its state directory, which a missing one's hint names.
func RootEngineKey(h FilesHost, stateDir, goos string, opened ConfigDir, now func() time.Time, stateDirMode os.FileMode) ([]byte, error) {
	cfg, _ := opened.(*rootConfigDir)
	if cfg == nil {
		return nil, errors.New("the config directory is not open")
	}
	want, err := cfg.dir.Owner()
	if err != nil {
		return nil, err
	}
	d, err := h.OSOpenTrustedDir(stateDir, cfg.trusted, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, missingStateDir(stateDir, goos, want, stateDirMode)
	}
	if err != nil {
		return nil, fmt.Errorf("the state directory %s is refused: %w", stateDir, err)
	}
	defer d.Close()
	dirUID, err := d.Owner()
	if err != nil {
		return nil, err
	}
	if dirUID != want {
		return nil, fmt.Errorf("the state directory %s is owned by uid %d, not uid %d (the owner of the config directory %s)", stateDir, dirUID, want, cfg.dir.Path())
	}
	for range 2 {
		keys, err := readRootKeyFile(d, dirUID)
		if !errors.Is(err, fs.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return keys.PublicKeySPKI(), nil
		}
		raw, keys, err := channel.NewKeyFile(now)
		if err != nil {
			return nil, err
		}
		err = d.CreateFile(channel.KeyFileName, raw, channel.KeyFileMode, CredentialOwner(dirUID))
		clear(raw)
		if err == nil {
			return keys.PublicKeySPKI(), nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("the engine's key file keeps changing; run basalt init --remote again")
}

// missingStateDir says how to make a missing state directory. The service
// manager makes only the default one (systemd's StateDirectory, the launchd
// install's directories); a config elsewhere (--config) keeps its state
// next to it, which nothing makes for the engine's user (owner).
func missingStateDir(stateDir, goos string, owner int, stateDirMode os.FileMode) error {
	if stateDir == config.DefaultStateDir(goos) {
		return fmt.Errorf("the state directory %s does not exist yet; start the engine's service once (it makes it), then run basalt init --remote again", stateDir)
	}
	return fmt.Errorf("the state directory %s does not exist yet; make it for the engine's user (sudo install -d -m %04o -o %d %s), then run basalt init --remote again",
		stateDir, stateDirMode, owner, stateDir)
}

// readRootKeyFile reads the key file in the state directory d, owned by
// dirUID: an error wrapping fs.ErrNotExist when there is none.
func readRootKeyFile(d TrustedDir, dirUID int) (*channel.EngineKeys, error) {
	f, err := config.OpenPlainAt(d, channel.KeyFileName, nil)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, _, err := ownerfile.ReadOpen(f, ownerfile.Rules{
		Owners: []int{dirUID}, OwnerName: fmt.Sprintf("uid %d (the owner of %s)", dirUID, d.Path()), MaxBytes: rootKeyFileMax,
	})
	defer clear(raw)
	if err != nil {
		switch re := ownerfile.Refusal(err); {
		case re != nil && re.Rule == ownerfile.Owner:
			return nil, fmt.Errorf("%s is %w", f.Name(), err)
		case re != nil && re.Rule == ownerfile.Mode:
			return nil, fmt.Errorf("%s is mode %o; it must be readable by the engine's user only (0600)", f.Name(), re.Perm)
		}
		return nil, fmt.Errorf("%s: %w", f.Name(), err)
	}
	return channel.ParseKeyFile(f.Name(), raw)
}

// rootKeyFileMax bounds what root reads of the key file (a valid one is
// well under 1 KiB; ParseKeyFile refuses more than 8 KiB).
const rootKeyFileMax = 8 << 10
