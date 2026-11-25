package guardmodel

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Plugin approval ledger kinds (schema version 5). Only the guard's plugin
// approval functions write them; record_plugin_event refuses both.
const (
	PluginApprovalPending PluginEventKind = "PLUGIN_APPROVAL_PENDING"
	PluginApproved        PluginEventKind = "PLUGIN_APPROVED"
)

// Details of the guard's plugin approval refusals: BS007 NOT_ALLOWED with
// DetailUnknownAgent or DetailTooManyPending from open_plugin_approval,
// BS005 APPROVAL_INVALID with DetailApprovalNotFound, DetailApprovalCancelled
// or DetailAlreadyApproved from submit_plugin_approval. They are the
// Postgres guard's details, here only because the plugin service still
// reads them from the store's error; they move to the guard adapter when
// the plugin's port answers typed refusals.
const (
	DetailUnknownAgent      = "UNKNOWN_AGENT"
	DetailTooManyPending    = "TOO_MANY_PENDING"
	DetailApprovalNotFound  = "NOT_FOUND"
	DetailApprovalCancelled = "CANCELLED"
	DetailAlreadyApproved   = "ALREADY_APPROVED"
)

// PluginApprovalStatus is a plugin approval's state in
// agent_plugin_approvals.
type PluginApprovalStatus string

// Plugin approval states.
const (
	PluginApprovalStatusPending   PluginApprovalStatus = "PENDING"
	PluginApprovalStatusApproved  PluginApprovalStatus = "APPROVED"
	PluginApprovalStatusCancelled PluginApprovalStatus = "CANCELLED"
	// PluginApprovalStatusExpired is a pending approval past its expiry.
	PluginApprovalStatusExpired PluginApprovalStatus = "EXPIRED"
)

// PluginApprovalDetail is what open_plugin_approval takes: the binding's
// keys agents to signerKeyId (CONTRACT.md, What a plugin approval binds).
// Agents are agent:<name> names of this database's agents (CONTRACT.md,
// Stores, Agent names). The guard refuses unsorted
// lists; OpenPluginApproval sorts copies of them first.
type PluginApprovalDetail struct {
	Agents         []string `json:"agents"`
	Name           string   `json:"name"`
	Instance       string   `json:"instance"`
	Version        string   `json:"version"`
	ManifestSHA256 string   `json:"manifestSha256"`
	Hooks          []string `json:"hooks"`
	// Roles are wire.detect's roles, present exactly with that hook.
	Roles     []string         `json:"roles,omitempty"`
	Egress    []string         `json:"egress"`
	Endpoint  PluginEndpoint   `json:"endpoint"`
	Isolation *PluginIsolation `json:"isolation,omitempty"`
	// Signer is PluginSignerKnown with SignerKeyID, or PluginSignerUnknown
	// without.
	Signer      string `json:"signer"`
	SignerKeyID string `json:"signerKeyId,omitempty"`
}

// PluginSettings is an entry's settings, the object Postgres turns into the
// settings text: each key only when the entry sets it. Config is carried
// as engine.json holds it, never decoded and encoded again, so a number
// in it keeps how it was written. The two numbers are values.
type PluginSettings struct {
	Config        json.RawMessage `json:"config,omitempty"`
	Auth          *PluginAuth     `json:"auth,omitempty"`
	TimeoutMs     *int            `json:"timeoutMs,omitempty"`
	MinConfidence *float64        `json:"minConfidence,omitempty"`
}

// PluginAuth is a remote entry's auth setting.
type PluginAuth struct {
	CredentialFile string `json:"credentialFile"`
}

// PluginApproval is an opened plugin approval: the texts Postgres built,
// for the link, and when the pending approval expires.
type PluginApproval struct {
	ID           uuid.UUID
	BindingText  string
	SettingsText string
	ExpiresAt    time.Time
}

// PluginApprovalResponse is the person's passkey assertion over a plugin
// approval's binding, as the page's signed response carries it.
type PluginApprovalResponse struct {
	ApprovalID uuid.UUID
	Assertion  passkey.Assertion
}

// PluginApprovalBound is what a plugin approval binds for one entry, as
// the PLUGIN_APPROVAL_PENDING detail records it: the fields the engine
// matches at start (no agents: the record names none).
type PluginApprovalBound struct {
	Name           string           `json:"name"`
	Instance       string           `json:"instance"`
	Version        string           `json:"version"`
	ManifestSHA256 string           `json:"manifestSha256"`
	SettingsSHA256 string           `json:"settingsSha256"`
	Hooks          []string         `json:"hooks"`
	Roles          []string         `json:"roles,omitempty"`
	Egress         []string         `json:"egress"`
	Endpoint       PluginEndpoint   `json:"endpoint"`
	Isolation      *PluginIsolation `json:"isolation,omitempty"`
	Signer         string           `json:"signer"`
	SignerKeyID    string           `json:"signerKeyId,omitempty"`
}

// PluginApprovalRecord is one row of agent_plugin_approvals for the
// calling agent role.
type PluginApprovalRecord struct {
	ApprovalID uuid.UUID
	Name       string
	Instance   string
	Status     PluginApprovalStatus
	OpenedAt   time.Time
	ExpiresAt  time.Time
	// ApprovedAt is set once a passkey signed it.
	ApprovedAt *time.Time
	// NamesCaller is whether the approval's agents hold the caller's role.
	NamesCaller bool
	// EndedAt is set when a PLUGIN_DISABLED of the entry, written by the
	// caller after the approval was signed, ended it for the caller.
	EndedAt *time.Time
	Bound   PluginApprovalBound
	// BindingText and SettingsText are empty except for the role that
	// opened the approval: they list the other agents.
	BindingText  string
	SettingsText string
}

// Ended reports whether the approval ended for the calling agent.
func (r PluginApprovalRecord) Ended() bool { return r.EndedAt != nil }
