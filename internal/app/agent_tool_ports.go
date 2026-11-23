package app

import (
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// DevLocalPages reports whether engine.json sets devLocalPages: every
// personMessage then starts with the DEV_LOCAL_PAGES warning.
func (s *Service) DevLocalPages() bool { return s.deps.Status.DevLocalPages }

// StoreKind is the kind of the agent's store: query and write are served
// only for one that speaks SQL.
func (s *Service) StoreKind() action.StoreKind { return s.deps.Core.Store.Kind() }

// DescribeError keeps a describe failure within the codes describe declares
// (INVALID_ARGUMENT, NOT_FOUND, QUERY_TIMEOUT, UNAVAILABLE, INTERNAL).
func (s *Service) DescribeError(err error) error { return s.agent.DescribeError(err) }
