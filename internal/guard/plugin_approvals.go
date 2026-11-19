package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
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
// or DetailAlreadyApproved from submit_plugin_approval.
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
// Agents are role names of this database. The guard refuses unsorted
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
// approval's binding, as a basalt-plugin.1. code carries it.
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

// OpenPluginApproval opens a plugin approval for the agents in d, every one
// an agent role of q's database, with the entry's settings. Postgres
// validates both, builds the binding and settings texts, cancels an
// earlier pending approval of the same (name, instance) and appends
// PLUGIN_APPROVAL_PENDING to the caller's ledger. Refusals: BS008
// LEDGER_INPUT_INVALID for a detail or settings outside the contract, BS007
// NOT_ALLOWED with DetailUnknownAgent or DetailTooManyPending. It needs
// schema version PluginApprovalsVersion.
func OpenPluginApproval(ctx context.Context, q Querier, d PluginApprovalDetail, s PluginSettings) (PluginApproval, error) {
	d.Agents = sortedCopy(d.Agents)
	d.Hooks = sortedCopy(d.Hooks)
	d.Egress = sortedCopy(d.Egress)
	if d.Egress == nil {
		d.Egress = []string{}
	}
	if d.Roles != nil {
		d.Roles = sortedCopy(d.Roles)
	}
	detail, err := json.Marshal(d)
	if err != nil {
		return PluginApproval{}, fmt.Errorf("open plugin approval: %w", err)
	}
	settings, err := json.Marshal(s)
	if err != nil {
		return PluginApproval{}, fmt.Errorf("open plugin approval: settings: %w", err)
	}
	var a PluginApproval
	// Plain SQL: a set-returning function in FROM.
	err = q.QueryRow(ctx, `SELECT o.approval_id, o.binding_text, o.settings_text, o.expires_at
		FROM basalt_meta.open_plugin_approval($1::jsonb, $2::jsonb) AS o`, string(detail), string(settings)).
		Scan(&a.ID, &a.BindingText, &a.SettingsText, &a.ExpiresAt)
	if err != nil {
		return PluginApproval{}, err
	}
	return a, nil
}

func sortedCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// SubmitPluginApproval relays the person's passkey assertion for a plugin
// approval; Postgres verifies it and appends PLUGIN_APPROVED to the ledger
// of every agent the approval lists. Any agent role of the database may
// relay. It returns when the approval was signed. Refusals: BS005
// APPROVAL_INVALID (DetailApprovalNotFound, DetailApprovalCancelled,
// DetailAlreadyApproved, or a failed passkey check) and APPROVAL_EXPIRED.
func SubmitPluginApproval(ctx context.Context, q Querier, r PluginApprovalResponse) (time.Time, error) {
	sql, args, err := psql.Select().Column(sq.Expr(
		"basalt_meta.submit_plugin_approval(?::uuid, ?::bytea, ?::bytea, ?::bytea, ?::bytea)",
		r.ApprovalID.String(), r.Assertion.CredentialID, r.Assertion.AuthenticatorData,
		r.Assertion.ClientDataJSON, r.Assertion.Signature)).ToSql()
	if err != nil {
		return time.Time{}, fmt.Errorf("submit plugin approval: %w", err)
	}
	var at time.Time
	err = q.QueryRow(ctx, sql, args...).Scan(&at)
	return at, err
}

// pluginApprovalColumns are the agent_plugin_approvals columns
// scanPluginApproval reads, in order.
var pluginApprovalColumns = []string{
	"approval_id", "name", "instance", "status", "opened_at", "expires_at", "approved_at",
	"names_caller", "ended_at", "detail", "coalesce(binding_text, '')", "coalesce(settings_text, '')",
}

// ReadPluginApprovals returns, for the calling agent role and each
// (name, instance), the newest plugin approval that names it (by
// opened_at, then approval_id), in name and instance order. The engine
// serves an entry that requires approval only on such a record that is
// APPROVED, not ended, and matches the entry. It needs schema version
// PluginApprovalsVersion: on an older guard the view does not exist.
func ReadPluginApprovals(ctx context.Context, q Querier) ([]PluginApprovalRecord, error) {
	sql, args, err := psql.Select(pluginApprovalColumns...).
		Options("DISTINCT ON (name, instance)").
		From("basalt_meta.agent_plugin_approvals").
		Where("names_caller").
		OrderBy("name", "instance", "opened_at DESC", "approval_id DESC").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanPluginApproval)
}

// ReadPluginApproval returns one plugin approval the calling role may see
// (it names the role or the role opened it), and false when there is none.
func ReadPluginApproval(ctx context.Context, q Querier, id uuid.UUID) (PluginApprovalRecord, bool, error) {
	sql, args, err := psql.Select(pluginApprovalColumns...).
		From("basalt_meta.agent_plugin_approvals").
		Where(sq.Eq{"approval_id": id.String()}).ToSql()
	if err != nil {
		return PluginApprovalRecord{}, false, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return PluginApprovalRecord{}, false, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanPluginApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return PluginApprovalRecord{}, false, nil
	}
	return r, err == nil, err
}

func scanPluginApproval(row pgx.CollectableRow) (PluginApprovalRecord, error) {
	var r PluginApprovalRecord
	var status string
	var detail []byte
	if err := row.Scan(&r.ApprovalID, &r.Name, &r.Instance, &status, &r.OpenedAt, &r.ExpiresAt, &r.ApprovedAt,
		&r.NamesCaller, &r.EndedAt, &detail, &r.BindingText, &r.SettingsText); err != nil {
		return r, err
	}
	r.Status = PluginApprovalStatus(status)
	if err := json.Unmarshal(detail, &r.Bound); err != nil {
		return r, fmt.Errorf("plugin approval %s: detail: %w", r.ApprovalID, err)
	}
	return r, nil
}
