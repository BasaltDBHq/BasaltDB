package dictfile

import (
	"fmt"
	"io"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// masterRules are the key file's rules beyond ownerfile's fixed ones: owned
// by the engine's OS user (this process's effective user, decision M51-1),
// and no larger than the key.
var masterRules = ownerfile.Rules{MaxBytes: pii.MasterKeySize}

// LoadKeys reads k_master from path (pii.KeyFileName in the engine's
// stateDir) and derives the keys. When the file is missing it creates it
// first with pii.MasterKeySize bytes from random, mode 0600, once
// (ownerfile.ReadOrCreate), without ever replacing a file that exists. It
// refuses a key file that is not a regular file with one link, belongs to
// another user, has the wrong size, or (outside Windows) a mode wider than
// 0600. Errors name the path, never key bytes.
func LoadKeys(path string, random io.Reader) (*pii.Keys, error) {
	fill := func() ([]byte, error) {
		master := make([]byte, pii.MasterKeySize)
		if _, err := io.ReadFull(random, master); err != nil {
			clear(master)
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		return master, nil
	}
	master, _, err := ownerfile.ReadOrCreate(path, masterRules, fill, time.Now)
	if err != nil {
		return nil, keyErr(path, err)
	}
	defer clear(master)
	if len(master) != pii.MasterKeySize {
		return nil, fmt.Errorf("pii key %s must hold %d bytes, found %d", path, pii.MasterKeySize, len(master))
	}
	return pii.NewKeys(master)
}

// keyErr names the key file in err, keeping a refusal's own text.
func keyErr(path string, err error) error {
	if re := ownerfile.Refusal(err); re != nil {
		if re.Rule == ownerfile.TooLarge {
			return fmt.Errorf("pii key %s must hold %d bytes, found %d", path, pii.MasterKeySize, re.Size)
		}
		return fmt.Errorf("pii key %s: %w", path, re)
	}
	return fmt.Errorf("pii key %s: %w", path, err)
}
