//go:build unix

package trustdir

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Load reads every profile in configPath's trust.d: the profiles that
// loaded, and each file or directory refused with why. No trust.d is no
// operator profile and nothing refused.
func Load(configPath string) ([]*trustprofile.Profile, []trustprofile.Refused) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil, []trustprofile.Refused{{File: Path(configPath), Reason: err.Error()}}
	}
	dir := Path(abs)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	d, trusted, err := Open(abs, false)
	if err != nil {
		return nil, []trustprofile.Refused{{File: dir, Reason: err.Error()}}
	}
	defer d.Close()
	names, err := d.Names()
	if err != nil {
		return nil, []trustprofile.Refused{{File: dir, Reason: err.Error()}}
	}
	slices.Sort(names)
	var (
		ops     []*trustprofile.Profile
		refused []trustprofile.Refused
	)
	for _, name := range names {
		if !profileFile(name) {
			continue
		}
		full := filepath.Join(dir, name)
		if len(ops) == maxProfiles {
			refused = append(refused, trustprofile.Refused{File: full, Reason: fmt.Sprintf("trust.d holds more than %d profiles", maxProfiles)})
			continue
		}
		p, err := loadOne(d, name, trusted)
		if err != nil {
			refused = append(refused, trustprofile.Refused{File: full, Reason: err.Error()})
			continue
		}
		ops = append(ops, p)
	}
	return ops, refused
}

// profileFile reports whether name in trust.d is a profile: a *.json file
// that is not hidden (a write in progress is a hidden temporary file).
func profileFile(name string) bool {
	return strings.HasSuffix(name, ".json") && !strings.HasPrefix(name, ".")
}

// Open opens configPath's trust.d under the rules, made (mode 0700, owned
// by the config directory's owner) when create is set and it is missing,
// with the owner its files must have (or root).
func Open(configPath string, create bool) (*service.TrustedDir, int, error) {
	cfgDir := filepath.Dir(configPath)
	trusted, err := owner(cfgDir)
	if err != nil {
		return nil, 0, fmt.Errorf("the config directory %s: %w", cfgDir, err)
	}
	d, err := service.OpenTrustedDir(Path(configPath), trusted, create)
	if err != nil {
		return nil, 0, fmt.Errorf("%s is refused: %w", Path(configPath), err)
	}
	return d, trusted, nil
}

// owner is the uid that owns path, a link itself rather than its target.
func owner(path string) (int, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read its owner")
	}
	return int(st.Uid), nil
}

func loadOne(d *service.TrustedDir, name string, trusted int) (*trustprofile.Profile, error) {
	raw, err := Read(d, name, trusted, trustprofile.MaxProfileBytes)
	if err != nil {
		return nil, err
	}
	p, err := trustprofile.Parse(raw, trustprofile.Operator, func(file string) ([]byte, error) {
		return Read(d, file, trusted, trustprofile.MaxRootFileBytes)
	})
	if err != nil {
		return nil, err
	}
	if err := trustprofile.CheckFileName(name, p.Name); err != nil {
		return nil, err
	}
	return p, nil
}

// Read is the file name in d, opened without following a link, a regular
// file with one link, owned by root or trusted and not writable by group or
// others, read through the descriptor that was checked, up to limit bytes.
func Read(d *service.TrustedDir, name string, trusted int, limit int64) ([]byte, error) {
	f, err := config.OpenPlainAt(d, name, func(f *os.File) error { return config.CheckTrustedConfig(f, trusted) })
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", f.Name(), limit)
	}
	return b, nil
}
