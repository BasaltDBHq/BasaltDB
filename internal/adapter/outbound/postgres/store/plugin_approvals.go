package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// readPluginApprovalRaw is ReadPluginApproval before MapError.
func (s *Store) readPluginApprovalRaw(ctx context.Context, id uuid.UUID) (guard.PluginApprovalRecord, bool, error) {
	return guard.ReadPluginApproval(ctx, s.db, id)
}

// submitPluginApprovalRaw is SubmitPluginApproval before MapError.
func (s *Store) submitPluginApprovalRaw(ctx context.Context, r guard.PluginApprovalResponse) (time.Time, error) {
	return guard.SubmitPluginApproval(ctx, s.db, r)
}
