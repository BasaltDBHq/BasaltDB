// Package keyfile keeps the engine's channel keys (channel.EngineKeys) in
// <stateDir>/channel.json (CONTRACT.md, Vault channel, Engine keys). It
// refuses a file, or a directory, someone else could have changed: the
// content checks are channel.ParseKeyFile's.
package keyfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

const (
	// dirWritableMask is the write bits for group and others.
	dirWritableMask os.FileMode = 0o022
	// keyFileMax bounds what is read; a valid file is well under 1 KiB.
	keyFileMax = channel.KeyFileMax
	// goosWindows is runtime.GOOS on Windows, where modes are not checked.
	goosWindows = "windows"
)

// checkStateDir refuses a key file's directory unless it is a directory
// (not a link to one) owned by the engine's user that neither group nor
// others can write: whoever can write it can swap the key file.
func checkStateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory: %w", reason(err))
	}
	return checkStateDirInfo(fi)
}

func checkStateDirInfo(fi os.FileInfo) error {
	if !fi.IsDir() {
		return errors.New("the state directory must be a directory, not a link")
	}
	if runtime.GOOS == goosWindows {
		return nil
	}
	if err := ownerfile.CheckOwner(fi, keyRules); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if fi.Mode().Perm()&dirWritableMask != 0 {
		return fmt.Errorf("state directory is mode %o; group and others must not be able to write it", fi.Mode().Perm())
	}
	return nil
}

// reason drops the path a *fs.PathError repeats. A refusal is its own text.
func reason(err error) error {
	if re := ownerfile.Refusal(err); re != nil {
		return re
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func keyFileErr(path string, err error) error {
	return fmt.Errorf("%w: %s: %w", channel.ErrKeyFile, path, err)
}

// keyRules are the key file's rules beyond ownerfile's fixed ones: owned by
// the engine's OS user (this process's effective user) and of a sane size.
var keyRules = ownerfile.Rules{MaxBytes: keyFileMax}

// LoadOrCreateKeys returns the engine's keys from path, creating the file
// with fresh keys when it does not exist (CONTRACT.md, Vault channel, Engine
// keys: made on the engine's first start, whatever vault says), once
// (ownerfile.ReadOrCreate): a temporary file in the same directory (mode
// 0600, fsync) hard-linked to path, so the file appears whole or not at all,
// and a file another process created first is kept and loaded instead. A
// file that exists is never replaced: one in a directory another user owns
// or others can write, one that is not a regular file with one link,
// belongs to another user, grants group or other access, cannot be read,
// fails the schema, whose engineId is not its signing key's or whose
// boxKeySig does not verify is refused with channel.ErrKeyFile and left
// untouched.
func LoadOrCreateKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	if err := checkStateDir(filepath.Dir(path)); err != nil {
		return nil, keyFileErr(path, err)
	}
	fill := func() ([]byte, error) {
		raw, _, err := channel.NewKeyFile(now)
		if err != nil {
			return nil, fmt.Errorf("make keys: %w", err)
		}
		return raw, nil
	}
	raw, _, err := ownerfile.ReadOrCreate(path, keyRules, fill, now)
	if err != nil {
		return nil, keyFileErr(path, reason(err))
	}
	defer clear(raw)
	return channel.ParseKeyFile(path, raw)
}
