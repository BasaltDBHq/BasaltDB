package agent

import (
	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// CheckLink reports whether secret is the live link secret of one of this
// agent's items.
func (s *Service) CheckLink(id uuid.UUID, secret string) bool {
	return s.delivery.CheckLink(id, secret)
}

// PageFailure is err as the pages answer it: the contract's error body with
// the person's message and the steps the catalog gives it.
func (s *Service) PageFailure(err error) *toolresult.ToolError {
	return s.delivery.PageFailure(err)
}
