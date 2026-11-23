package plugin

import (
	"encoding/json"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"

	"github.com/google/uuid"
)

// CodePluginRefused is a plugin method refused, with a Reason.
const CodePluginRefused Code = "PLUGIN_REFUSED"

// Refused is PLUGIN_REFUSED with reason.
func Refused(reason, message string) *PersonError {
	return &PersonError{Code: CodePluginRefused, Reason: reason, Message: message}
}

// Scope is the agents a plugin request may reach: nil for a person, who
// may name every agent; else the agents whose osUser is the peer's uid
// (SM-4).
type Scope map[string]bool

// Allows reports whether the scope reaches agent.
func (s Scope) Allows(agent string) bool { return s == nil || s[agent] }

// AllowsAll reports whether the scope reaches every one of agents.
func (s Scope) AllowsAll(agents []string) bool {
	for _, a := range agents {
		if !s.Allows(a) {
			return false
		}
	}
	return true
}

// PluginUploadBeginResult is PLUGIN_UPLOAD_BEGIN's result.
type PluginUploadBeginResult struct {
	UploadID       uuid.UUID `json:"uploadId"`
	ExpiresAt      time.Time `json:"expiresAt"`
	MaxPartBytes   int       `json:"maxPartBytes"`
	MaxUploadBytes int       `json:"maxUploadBytes"`
}

// PluginUploadPartParams are PLUGIN_UPLOAD_PART's params.
type PluginUploadPartParams struct {
	UploadID uuid.UUID `json:"uploadId"`
	Path     string    `json:"path"`
	Offset   int64     `json:"offset"`
	Data     string    `json:"data"`
}

// PluginUploadPartResult is PLUGIN_UPLOAD_PART's result.
type PluginUploadPartResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// PluginSettings are an engine-kept entry's settings: no auth.
type PluginSettings struct {
	Config        json.RawMessage `json:"config,omitempty"`
	TimeoutMs     *int            `json:"timeoutMs,omitempty"`
	MinConfidence *float64        `json:"minConfidence,omitempty"`
}

// PluginOpenParams are PLUGIN_OPEN's params.
type PluginOpenParams struct {
	UploadID    *uuid.UUID      `json:"uploadId,omitempty"`
	Name        string          `json:"name"`
	Instance    string          `json:"instance"`
	Agents      []string        `json:"agents"`
	Settings    *PluginSettings `json:"settings,omitempty"`
	Executables []string        `json:"executables,omitempty"`
}

// PluginDatabase names a database as the commands show it.
type PluginDatabase struct {
	Host string `json:"host"`
	Name string `json:"name"`
}

// PluginOpenRefusal is an approval the engine could not open after the
// entry was written.
type PluginOpenRefusal struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// PluginOpenedApproval is one database's approval.
type PluginOpenedApproval struct {
	Database     PluginDatabase     `json:"database"`
	Agents       []string           `json:"agents"`
	ApprovalID   *uuid.UUID         `json:"approvalId,omitempty"`
	ExpiresAt    *time.Time         `json:"expiresAt,omitempty"`
	BindingText  string             `json:"bindingText,omitempty"`
	SettingsText string             `json:"settingsText,omitempty"`
	Refused      *PluginOpenRefusal `json:"refused,omitempty"`
}

// PluginOpenResult is PLUGIN_OPEN's result.
type PluginOpenResult struct {
	Name      string                 `json:"name"`
	Instance  string                 `json:"instance"`
	Version   string                 `json:"version"`
	Narrowed  bool                   `json:"narrowed"`
	Approvals []PluginOpenedApproval `json:"approvals"`
}

// PluginListResult is PLUGIN_LIST's result.
type PluginListResult struct {
	Plugins []PluginListed `json:"plugins"`
	Problem string         `json:"problem,omitempty"`
}

// Sources of a listed entry.
const (
	SourceConfig = "CONFIG"
	SourceEngine = "ENGINE"
)

// Health of a listed entry: what the running engine knows of it.
const (
	// HealthReady: the engine runs the entry and its plugin answers.
	HealthReady = "READY"
	// HealthUnavailable: the engine runs the entry, or keeps trying to
	// start it, and its plugin does not answer now.
	HealthUnavailable = "UNAVAILABLE"
	// HealthNotStarted: the engine does not run the entry (turned off, not
	// approved, refused at its check, added since the engine last read its
	// entries, or another entry of the same name and instance runs).
	HealthNotStarted = "NOT_STARTED"
)

// PluginListed is one entry of PLUGIN_LIST.
type PluginListed struct {
	Name        string          `json:"name"`
	Instance    string          `json:"instance"`
	Source      string          `json:"source"`
	Enabled     bool            `json:"enabled"`
	Agents      []string        `json:"agents"`
	Version     string          `json:"version"`
	Signer      string          `json:"signer,omitempty"`
	SignerKeyID string          `json:"signerKeyId,omitempty"`
	Endpoint    json.RawMessage `json:"endpoint"`
	Isolation   json.RawMessage `json:"isolation,omitempty"`
	// Health is HealthReady, HealthUnavailable or HealthNotStarted.
	Health   string               `json:"health"`
	Approval PluginListedApproval `json:"approval"`
	// Serving is what the running engine serves of the entry, per agent:
	// the approval it is served on and whether the plugin answers READY.
	// Absent when it serves the entry to no agent.
	Serving []PersonPluginServing `json:"serving,omitempty"`
}

// PluginListedApproval is an entry's approval state per listed agent.
type PluginListedApproval struct {
	Required bool                `json:"required"`
	Agents   []PluginAgentStatus `json:"agents"`
}

// PluginAgentStatus is one agent's newest approval of an entry.
type PluginAgentStatus struct {
	Agent      string     `json:"agent"`
	State      string     `json:"state"`
	ApprovalID *uuid.UUID `json:"approvalId,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// PersonPluginServing is one agent an entry is served to.
type PersonPluginServing struct {
	Agent      string     `json:"agent"`
	ApprovalID *uuid.UUID `json:"approvalId,omitempty"`
	Ready      bool       `json:"ready"`
}

// PluginApproveParams are PLUGIN_APPROVE's params: the approval and the
// person's passkey assertion.
type PluginApproveParams struct {
	ApprovalID uuid.UUID
	Assertion  passkey.Assertion
}

// PluginApproveResult is PLUGIN_APPROVE's result.
type PluginApproveResult struct {
	ApprovalID uuid.UUID `json:"approvalId"`
	Status     string    `json:"status"`
	ApprovedAt time.Time `json:"approvedAt"`
}

// PluginEntryParams name an entry: PLUGIN_DISABLE and PLUGIN_REMOVE.
type PluginEntryParams struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
}

// PluginEntryResult is PLUGIN_DISABLE's result (Enabled false) or
// PLUGIN_REMOVE's (Removed true).
type PluginEntryResult struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Removed  *bool  `json:"removed,omitempty"`
}
