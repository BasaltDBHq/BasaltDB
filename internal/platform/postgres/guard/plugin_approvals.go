package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// OpenPluginApproval opens a plugin approval for the agents in d, each
// agent:<name> of an agent role of q's database, with the entry's settings. Postgres
// validates both, builds the binding and settings texts, cancels an
// earlier pending approval of the same (name, instance) and appends
// PLUGIN_APPROVAL_PENDING to the caller's ledger. Refusals: BS008
// LEDGER_INPUT_INVALID for a detail or settings outside the contract, BS007
// NOT_ALLOWED with DetailUnknownAgent or DetailTooManyPending. It needs
// schema version PluginApprovalsVersion.
func OpenPluginApproval(ctx context.Context, q Querier, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error) {
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
		return guardmodel.PluginApproval{}, fmt.Errorf("open plugin approval: %w", err)
	}
	settings, err := json.Marshal(s)
	if err != nil {
		return guardmodel.PluginApproval{}, fmt.Errorf("open plugin approval: settings: %w", err)
	}
	var a guardmodel.PluginApproval
	// Plain SQL: a set-returning function in FROM.
	err = q.QueryRow(ctx, `SELECT o.approval_id, o.binding_text, o.settings_text, o.expires_at
		FROM basalt_meta.open_plugin_approval($1::jsonb, $2::jsonb) AS o`, string(detail), string(settings)).
		Scan(&a.ID, &a.BindingText, &a.SettingsText, &a.ExpiresAt)
	if err != nil {
		return guardmodel.PluginApproval{}, err
	}
	return a, nil
}

// PluginSettingsSHA256 is the settingsSha256 of an entry's settings s as
// the engine recomputes it at start (CONTRACT.md, What a plugin approval
// binds): s goes to q's database as jsonb, its text comes back, and the
// lowercase hex SHA-256 is taken of that text, so both sides hash the bytes
// Postgres writes. Go never builds the text itself.
func PluginSettingsSHA256(ctx context.Context, q Querier, s guardmodel.PluginSettings) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("plugin settings: %w", err)
	}
	var text string
	// Plain SQL: a cast, no table. Both types are qualified: the agent's
	// connection has its own search_path, and a type of its own named text
	// with a cast from jsonb would decide the text otherwise. A cast between
	// two pg_catalog types needs the owner of one of them to create it.
	if err := q.QueryRow(ctx, `SELECT $1::pg_catalog.jsonb::pg_catalog.text`, string(raw)).Scan(&text); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]), nil
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
func SubmitPluginApproval(ctx context.Context, q Querier, r guardmodel.PluginApprovalResponse) (time.Time, error) {
	sql, args, err := sqlport.Builder.Select().Column(sq.Expr(
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
	"withdrawn_at", "coalesce(withdraw_reason, '')",
}

// ReadPluginApprovals returns, for the calling agent role and each
// (name, instance), the newest plugin approval that names it (by
// opened_at, then approval_id), in name and instance order. The engine
// serves an entry that requires approval only on such a record that is
// APPROVED, not ended, and matches the entry. It needs schema version
// PluginApprovalsVersion: on an older guard the view does not exist.
func ReadPluginApprovals(ctx context.Context, q Querier) ([]guardmodel.PluginApprovalRecord, error) {
	sql, args, err := sqlport.Builder.Select(pluginApprovalColumns...).
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
func ReadPluginApproval(ctx context.Context, q Querier, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	sql, args, err := sqlport.Builder.Select(pluginApprovalColumns...).
		From("basalt_meta.agent_plugin_approvals").
		Where(sq.Eq{"approval_id": id.String()}).ToSql()
	if err != nil {
		return guardmodel.PluginApprovalRecord{}, false, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return guardmodel.PluginApprovalRecord{}, false, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanPluginApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return guardmodel.PluginApprovalRecord{}, false, nil
	}
	return r, err == nil, err
}

func scanPluginApproval(row pgx.CollectableRow) (guardmodel.PluginApprovalRecord, error) {
	var r guardmodel.PluginApprovalRecord
	var status string
	var detail []byte
	if err := row.Scan(&r.ApprovalID, &r.Name, &r.Instance, &status, &r.OpenedAt, &r.ExpiresAt, &r.ApprovedAt,
		&r.NamesCaller, &r.EndedAt, &detail, &r.BindingText, &r.SettingsText, &r.WithdrawnAt, &r.WithdrawReason); err != nil {
		return r, err
	}
	r.Status = guardmodel.PluginApprovalStatus(status)
	if err := json.Unmarshal(detail, &r.Bound); err != nil {
		return r, fmt.Errorf("plugin approval %s: detail: %w", r.ApprovalID, err)
	}
	return r, nil
}
