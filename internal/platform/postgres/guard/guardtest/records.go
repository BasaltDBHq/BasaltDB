package guardtest

import (
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// RecordEngine records an engine's signing key (its SPKI DER) with the
// admin connection and returns its engine id, as record_engine does in the
// install transaction a setup runs (guard.RecordEngineStatement). Postgres
// refuses a malformed key and a revoked engine (BS008) and appends
// ENGINE_RECORDED when it inserts a key.
func RecordEngine(ctx context.Context, q guard.Querier, publicKey []byte) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT basalt_meta.record_engine($1::bytea)`, publicKey).Scan(&id)
	return id, err
}

// RevokeEngine revokes an engine with the admin connection and returns how
// many engines remain not revoked. No command or page calls revoke_engine;
// the guard still has it. Postgres refuses an unknown or already revoked id
// alike (BS008, ENGINE_UNKNOWN) and appends ENGINE_REVOKED.
func RevokeEngine(ctx context.Context, q guard.Querier, engineID string) (int, error) {
	var remaining int
	err := q.QueryRow(ctx, `SELECT basalt_meta.revoke_engine($1::text)`, engineID).Scan(&remaining)
	return remaining, err
}

// RecordSetup records s with the admin connection and returns the seq of
// its AGENT_SETUP ledger row, as guard.RecordSetupStatement does in the
// transaction that applies the code. Postgres refuses a used, superseded,
// expired or forged-time code with SETUP_REFUSED (guard.SetupRefusal).
func RecordSetup(ctx context.Context, q guard.Querier, n guardmodel.Names, s guardmodel.Setup) (int64, error) {
	if err := n.Validate(); err != nil {
		return 0, err
	}
	var agent any // NULL for UPGRADE
	if s.Agent != "" {
		role, err := n.Agent(s.Agent)
		if err != nil {
			return 0, err
		}
		agent = role
	}
	var seq int64
	err := q.QueryRow(ctx, `SELECT basalt_meta.record_setup($1::uuid, $2::text, $3::name, $4::int, $5::timestamptz)`,
		s.ID, s.Kind, agent, s.GuardVersion, s.ExpiresAt).Scan(&seq)
	return seq, err
}

// Uninstall drops the guard's and agents' RLS policies and basalt_meta (and with it
// every guard trigger), then the agent roles, the group and the owner.
// Roles are cluster objects that
// DROP SCHEMA leaves behind; DROP OWNED BY revokes their grants in this
// database. A role with privileges in another database fails to drop.
// It runs what guard.PlanUninstall plans, in order.
func Uninstall(ctx context.Context, q guard.Querier, n guardmodel.Names) error {
	drops, err := guard.PlanUninstall(ctx, q, n)
	if err != nil {
		return err
	}
	for _, sql := range drops {
		if _, err := q.Exec(ctx, sql); err != nil {
			return fmt.Errorf("uninstall: %w", err)
		}
	}
	return nil
}
