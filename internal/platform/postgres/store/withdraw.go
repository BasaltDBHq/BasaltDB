package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// WithdrawApproval withdraws a held write the agent's role holds while it
// waits for the person (basalt_meta.withdraw_approval): when it was
// withdrawn, nil when it was no longer waiting.
func (s *Store) WithdrawApproval(ctx context.Context, id uuid.UUID, reason string) (*time.Time, error) {
	at, err := guard.WithdrawApproval(ctx, s.db, id, reason)
	return at, MapError(err)
}

// WithdrawRevert withdraws a revert the agent's role prepared while it
// waits for the person's signature (basalt_meta.withdraw_revert).
func (s *Store) WithdrawRevert(ctx context.Context, id uuid.UUID, reason string) (*time.Time, error) {
	at, err := guard.WithdrawRevert(ctx, s.db, id, reason)
	return at, MapError(err)
}

// WithdrawPluginApproval withdraws a pending plugin approval the agent's
// role opened (basalt_meta.withdraw_plugin_approval).
func (s *Store) WithdrawPluginApproval(ctx context.Context, id uuid.UUID, reason string) (*time.Time, error) {
	at, err := guard.WithdrawPluginApproval(ctx, s.db, id, reason)
	return at, MapError(err)
}
