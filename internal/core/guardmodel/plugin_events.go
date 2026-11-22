package guardmodel

// PluginEventKind is a plugin ledger event (CONTRACT.md, Plugins, In the
// ledger).
type PluginEventKind string

// Plugin ledger events, written with record_plugin_event (version 3).
const (
	PluginEnabled    PluginEventKind = "PLUGIN_ENABLED"
	PluginDisabled   PluginEventKind = "PLUGIN_DISABLED"
	PluginChanged    PluginEventKind = "PLUGIN_CHANGED"
	PluginTrustAdded PluginEventKind = "PLUGIN_TRUST_ADDED"
	// PluginTrustRemoved needs schema version 4.
	PluginTrustRemoved PluginEventKind = "PLUGIN_TRUST_REMOVED"
)

// Endpoint kinds and isolation values of a plugin event's detail.
const (
	PluginEndpointLocal  = "LOCAL"
	PluginEndpointRemote = "REMOTE"

	PluginFilesOSUser = "OS_USER"
	PluginFilesNone   = "NONE"

	PluginNetworkEnforced    = "ENFORCED"
	PluginNetworkDeclared    = "DECLARED"
	PluginNetworkNotEnforced = "NOT_ENFORCED"

	// Signer states of a plugin event or approval (schema version 5).
	PluginSignerKnown   = "KNOWN"
	PluginSignerUnknown = "UNKNOWN"
)

// PluginDetail is the detail of a plugin entry event (PLUGIN_ENABLED,
// PLUGIN_DISABLED, PLUGIN_CHANGED), api/plugin/events.schema.json. It
// holds no config value and names no agent.
type PluginDetail struct {
	Name           string `json:"name"`
	Instance       string `json:"instance"`
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifestSha256"`
	// Signer is written only for an entry that requires approval (schema
	// version 5; an older guard refuses the key): PluginSignerKnown with
	// SignerKeyID, or PluginSignerUnknown without. Without Signer,
	// SignerKeyID is required.
	Signer      string   `json:"signer,omitempty"`
	SignerKeyID string   `json:"signerKeyId,omitempty"`
	Hooks       []string `json:"hooks"`
	// Roles are wire.detect's declared roles; omitted otherwise.
	Roles []string `json:"roles,omitempty"`
	// Egress is never nil: the guard wants an array, empty for none.
	Egress    []string         `json:"egress"`
	Endpoint  PluginEndpoint   `json:"endpoint"`
	Isolation *PluginIsolation `json:"isolation,omitempty"`
	Model     *PluginModel     `json:"model,omitempty"`
}

// PluginEndpoint is where an entry runs: LOCAL, or REMOTE with the host:port.
type PluginEndpoint struct {
	Kind string `json:"kind"`
	Host string `json:"host,omitempty"`
}

// PluginIsolation is a local entry's isolation.
type PluginIsolation struct {
	Files   string `json:"files"`
	Network string `json:"network"`
}

// PluginModel is the model a plugin reports.
type PluginModel struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PluginRecord is the latest plugin entry event of one (name, instance) in
// an agent's ledger.
type PluginRecord struct {
	Kind   PluginEventKind
	Detail PluginDetail
}

// Enabled reports whether the record leaves the entry served: its latest
// event is PLUGIN_ENABLED or PLUGIN_CHANGED.
func (r PluginRecord) Enabled() bool { return r.Kind != PluginDisabled }

// PluginRecords is what an agent's ledger says of its plugins: the latest
// event of each entry, in name and instance order, and the trust keys
// recorded as added.
type PluginRecords struct {
	Entries []PluginRecord
	// TrustKeys are the keys the ledger records as trusted: their latest
	// PLUGIN_TRUST_ADDED or PLUGIN_TRUST_REMOVED is an ADDED. Sorted.
	TrustKeys []string
}

// EnabledPlugins are the entries the records leave served, in name and
// instance order.
func (r PluginRecords) EnabledPlugins() []PluginDetail {
	var out []PluginDetail
	for _, e := range r.Entries {
		if e.Enabled() {
			out = append(out, e.Detail)
		}
	}
	return out
}
