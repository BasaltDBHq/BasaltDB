// Package agent is what the engine does for one agent on its own database:
// describe, and the queries and writes it runs, each on the agent's scoped
// credential. The tools that front it and the use cases of the other
// domains are served by internal/service/agent.
package agent

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Store is what the agent use cases read of the agent's store.
type Store interface {
	// Kind is the kind of store the agent is bound to.
	Kind() action.StoreKind
}

// Core is the part of the shared settings the agent use cases read, copied
// when the service is built.
type Core struct {
	Store    Store
	Commands guidance.Commands
	Errors   guidance.ErrorMap
}

// DescribeDeps is what the describe tool reads.
type DescribeDeps struct {
	// Catalog reads the database's structure for describe; optional, and
	// describe answers INTERNAL when nil.
	Catalog Catalog
	// Classes are the agent's PII classes for describe; optional, and
	// describe fails closed (INTERNAL) when nil: it cannot tell a SECRET
	// column.
	Classes ClassResolver
}

// Service is the describe use case: it reads the database's structure
// through its own port and holds only the dependencies it uses.
type Service struct {
	core Core
	deps *DescribeDeps
	// update is the newer release the engine knows of, as describe's overview
	// reports it; the status use case owns it and hands it in.
	update func() *guidance.UpdateInfo
}

// New returns the service over core and its dependency group. A nil Catalog
// or Classes in deps is replaced, in the group itself, by one that fails
// closed.
func New(core Core, deps *DescribeDeps, update func() *guidance.UpdateInfo) *Service {
	if deps.Catalog == nil {
		deps.Catalog = noCatalog{}
	}
	if deps.Classes == nil {
		deps.Classes = noClasses{}
	}
	return &Service{core: core, deps: deps, update: update}
}

// StatementTimeout is the agent's statement timeout, 0 when the service
// knows no catalog.
func (ds *Service) StatementTimeout() time.Duration {
	if ds.deps.Catalog == nil {
		return 0
	}
	return ds.deps.Catalog.Limits().StatementTimeout
}
