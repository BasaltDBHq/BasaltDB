package handoff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// key names a's canonical form without holding it: the probe cache keeps
// this, never the address.
func (a Address) key() string {
	c := a.Canonical()
	sum := sha256.Sum256([]byte(c.Host + "\n" + strconv.Itoa(c.Port) + "\n" + c.Database + "\n" + c.SupabaseRef))
	return hex.EncodeToString(sum[:])
}

// Cached is what the engine keeps of its last PREVIEW probe across
// processes (the engine, and basalt status while it is down): a hash of
// the address, never the address, the IP it resolved to, when, what the
// probe found, and the RATE_LIMITED wait.
type Cached struct {
	SetupID        string     `json:"setupId"`
	AddressKey     string     `json:"addressKey"`
	IP             netip.Addr `json:"ip"`
	At             time.Time  `json:"at"`
	Reason         string     `json:"reason,omitempty"`
	ChannelBinding bool       `json:"channelBinding,omitempty"`
	// Pinned is the SHA-256 of the pin the probe passed with, "" for none.
	Pinned    string    `json:"pinned,omitempty"`
	NotBefore time.Time `json:"notBefore"`
}

// ProbeCache keeps Cached between processes, so a reached PREVIEW address
// is probed once per flow whichever process collects it (CONTRACT.md, The
// engine and a connect-only code, Collecting).
type ProbeCache interface {
	Load(setupID string) (Cached, bool)
	Save(c Cached) error
}

// FileCache is a ProbeCache in the engine's state directory, a 0600 file
// of the engine's user.
type FileCache struct{ Dir string }

// ProbeCacheName is FileCache's file in the state directory.
const ProbeCacheName = "connect-probe.json"

// cacheDirMode is the state directory's mode when Save makes it.
const cacheDirMode = 0o700

func (f FileCache) path() string { return filepath.Join(f.Dir, ProbeCacheName) }

// Load is the cached probe of setupID; false for none, another setup, or a
// file it cannot read.
func (f FileCache) Load(setupID string) (Cached, bool) {
	raw, _, err := config.ReadOwnCredential(f.path())
	if err != nil {
		return Cached{}, false
	}
	var c Cached
	if json.Unmarshal([]byte(raw), &c) != nil || c.SetupID != setupID {
		return Cached{}, false
	}
	return c, true
}

// Save replaces the file with c.
func (f FileCache) Save(c Cached) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, cacheDirMode); err != nil {
		return err
	}
	return config.WriteFile(f.path(), raw)
}
