package handoff

import (
	"encoding/json"
	"net/netip"
	"time"
)

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

// CacheFile is the file a FileCache keeps its probe in, read and written
// whole (handofffiles.ProbeCacheFile in the engine's state directory).
type CacheFile interface {
	Read() (string, error)
	Write(raw []byte) error
}

// FileCache is a ProbeCache in one file.
type FileCache struct{ File CacheFile }

// Load is the cached probe of setupID; false for none, another setup, or a
// file it cannot read.
func (f FileCache) Load(setupID string) (Cached, bool) {
	raw, err := f.File.Read()
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
	return f.File.Write(raw)
}
