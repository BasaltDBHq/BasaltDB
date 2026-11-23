package agent

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// describeCase is the describe use case: it reads the database's
// structure through its own port and holds only the dependencies it uses.
type describeCase struct {
	core *CoreDeps
	deps *DescribeDeps
	// update is the newer release the engine knows of, as describe's overview
	// reports it; the status use case owns it and hands it in.
	update func() *UpdateInfo
}

func newDescribeCase(core *CoreDeps, deps *DescribeDeps, update func() *UpdateInfo) *describeCase {
	return &describeCase{core: core, deps: deps, update: update}
}

// DescribeOverview is the database's schemas with their table counts.
func (s *Service) DescribeOverview(ctx context.Context) (Overview, error) {
	return s.describe.DescribeOverview(ctx)
}

// DescribeResource is one table's structure.
func (s *Service) DescribeResource(ctx context.Context, resource, ifFingerprint string) (Resource, error) {
	return s.describe.DescribeResource(ctx, resource, ifFingerprint)
}

// DescribeSearch finds tables and columns by a word of their names.
func (s *Service) DescribeSearch(ctx context.Context, p DescribeSearchParams) (pagination.Page[SearchItem], error) {
	return s.describe.DescribeSearch(ctx, p)
}
