package app

import (
	"context"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// DescribeOverview is the database's schemas with their table counts.
func (s *Service) DescribeOverview(ctx context.Context) (agentsvc.Overview, error) {
	return s.agent.DescribeOverview(ctx)
}

// DescribeResource is one table's structure.
func (s *Service) DescribeResource(ctx context.Context, resource, ifFingerprint string) (agentsvc.Resource, error) {
	return s.agent.DescribeResource(ctx, resource, ifFingerprint)
}

// DescribeSearch finds tables and columns by a word of their names.
func (s *Service) DescribeSearch(ctx context.Context, p agentsvc.DescribeSearchParams) (pagination.Page[agentsvc.SearchItem], error) {
	return s.agent.DescribeSearch(ctx, p)
}
