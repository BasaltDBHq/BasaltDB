package app

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	piisvc "github.com/basaltdbhq/basaltdb/internal/pii"
)

// openPII opens the engine's PII state in stateDir (M5.1 plan, section 5):
// k_master in pii.key, created on first start and refused when its mode is
// wider than 0600 (the engine does not start), and the dictionary in pii/.
// It sets GOMEMLIMIT from the budget and writes status.json.
func openPII(stateDir string, p config.PII, log *slog.Logger) (*pii.FuseDictionary, error) {
	if err := os.MkdirAll(stateDir, engine.StateDirMode); err != nil {
		return nil, fmt.Errorf("pii: state directory %s: %w", stateDir, err)
	}
	keys, err := dictfile.LoadKeys(filepath.Join(stateDir, pii.KeyFileName), rand.Reader)
	if err != nil {
		return nil, err
	}
	opts := pii.DefaultDictionaryOptions(time.Now)
	opts.MaxMemoryBytes = p.MaxMemoryBytes()
	dict, err := dictfile.Open(stateDir, keys, opts)
	if err != nil {
		return nil, err
	}
	if why := dict.Discarded(); why != nil {
		log.Warn("pii: the saved dictionary was not usable; the first scan rebuilds it", "err", why)
	}
	if err := dict.WriteStatus(); err != nil {
		log.Warn("pii: could not write the dictionary status", "err", err)
	}
	piisvc.SetMemoryLimit(p, log)
	return dict, nil
}

// storeErrors maps errors like the Postgres store does (postgres.MapError),
// so the services see contract errors.
type storeErrors struct{}

func (storeErrors) MapError(err error) error { return store.MapError(err) }
