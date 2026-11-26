package revert

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// ListOpenReverts lists the role's PENDING and APPLYING reverts, for the
// approval use case's pending list.
func (rc *Service) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return rc.store.Records.ListOpenReverts(ctx, p)
}
