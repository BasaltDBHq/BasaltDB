package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// readPluginApprovalRaw is ReadPluginApproval before MapError.
func (s *Store) readPluginApprovalRaw(ctx context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	return guard.ReadPluginApproval(ctx, s.db, id)
}

// submitPluginApprovalRaw is SubmitPluginApproval before MapError.
func (s *Store) submitPluginApprovalRaw(ctx context.Context, r guardmodel.PluginApprovalResponse) (time.Time, error) {
	return guard.SubmitPluginApproval(ctx, s.db, r)
}
