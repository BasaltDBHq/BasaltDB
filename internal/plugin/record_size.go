package plugin

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

// Bounds of what an agent's ledger records of an entry (CONTRACT.md,
// Plugins, In the ledger): the guard refuses a version over 64 bytes and a
// detail over 4096 bytes as Postgres prints it. A manifest whose record
// could break either is refused here, so no plugin the person consents to
// can fail to be recorded, and so never be served.
const (
	maxVersionBytes = 64
	maxRecordBytes  = 4096
)

// worstRecordValues are the longest values an entry's record can hold
// besides the manifest's own: a 32-character instance, a manifest hash,
// a key id, and the longest isolation.
var (
	worstInstance = strings.Repeat("x", maxInstanceLen)
	worstSHA256   = strings.Repeat("0", sha256HexLen)
	worstKeyID    = strings.Repeat("A", keyIDLen)
)

const (
	maxInstanceLen = 32
	sha256HexLen   = 64
	keyIDLen       = 22
)

// recordBytes is the largest size, as the guard measures it, that an
// agent's ledger record of an entry with manifest m can take, whatever its
// instance, hash, signer and isolation.
func recordBytes(m Manifest) int {
	type endpoint struct {
		Kind string `json:"kind"`
		Host string `json:"host,omitempty"`
	}
	type isolation struct {
		Files   string `json:"files"`
		Network string `json:"network"`
	}
	d := struct {
		Name           string     `json:"name"`
		Instance       string     `json:"instance"`
		Version        string     `json:"version"`
		ManifestSHA256 string     `json:"manifestSha256"`
		SignerKeyID    string     `json:"signerKeyId"`
		Hooks          []string   `json:"hooks"`
		Roles          []string   `json:"roles,omitempty"`
		Egress         []string   `json:"egress"`
		Endpoint       endpoint   `json:"endpoint"`
		Isolation      *isolation `json:"isolation,omitempty"`
	}{
		Name: m.Name, Instance: worstInstance, Version: m.Version, ManifestSHA256: worstSHA256, SignerKeyID: worstKeyID,
		Hooks: slices.Sorted(maps.Keys(m.Hooks)), Egress: append([]string{}, m.Network.Egress...),
		Endpoint: endpoint{Kind: "REMOTE"},
	}
	if decl, ok := m.Hooks[string(HookWireDetect)]; ok {
		d.Roles = decl.Roles
	}
	if r := m.Endpoint.Remote; r != nil {
		d.Endpoint.Host, _ = RemoteHostPort(r.URL)
	} else {
		d.Isolation = &isolation{Files: "OS_USER", Network: "NOT_ENFORCED"}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return maxRecordBytes + 1
	}
	return len(b) + jsonbSpaces(b)
}

// jsonbSpaces is how many bytes Postgres adds when it prints compact JSON b
// as jsonb text: a space after each ':' and ',' outside strings.
func jsonbSpaces(b []byte) int {
	n, inString, escaped := 0, false, false
	for _, c := range b {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && (c == ':' || c == ','):
			n++
		}
	}
	return n
}

// recordFits refuses a manifest whose ledger record could exceed the
// guard's bounds.
func (p *manifestParser) recordFits() error {
	if len(p.m.Version) > maxVersionBytes {
		return badManifest("version must be at most 64 bytes")
	}
	if recordBytes(p.m) > maxRecordBytes {
		return badManifest("the manifest is too large to record in the ledger: shorten network.egress")
	}
	return nil
}
