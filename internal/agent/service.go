// Package agent is what the engine does for one agent on its own database:
// describe, and the runs, queries and writes it makes, each on the agent's
// scoped credential. The tools that front it are internal/agent/in/agentmcp;
// internal/app wires it with the use cases of the other domains.
package agent

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// StoreSet is the agent's store as the agent use cases read it, built by
// the wiring for the store's kind. The service may read Capabilities; it
// never switches on the kind.
type StoreSet struct {
	// Kind is the kind of store the agent is bound to, as describe reports it.
	Kind action.StoreKind
	// Family picks the tools the agent is served.
	Family       agentstore.Family
	Capabilities action.Capabilities
	// Language is the store's language: the check of a request, the texts
	// of its refusals and steps, and its resource names.
	Language Language
	// Data runs the reads and writes; without it every one fails as an
	// engine defect (INTERNAL).
	Data Data
	// Catalog reads the store's structure for describe; without it describe
	// answers INTERNAL.
	Catalog Catalog
	// Ledger is the ledger of the agent's runs.
	Ledger Ledger
	// Classes are the agent's PII classes for describe; without them
	// describe fails closed (INTERNAL): it cannot tell a SECRET field.
	Classes ClassResolver
	// Visibility says what the store hides from the agent (the
	// RLS_HIDES_ROWS warning); optional, nothing is hidden when nil.
	Visibility Visibility
}

type noPII struct{}

func (noPII) Observe(context.Context, []action.Column, []map[string]any) error { return nil }

func (noPII) ObserveReturned(context.Context, pii.Classes, []action.Column, []map[string]any) error {
	return nil
}

// Service runs one agent's describe, run, query and write calls. It holds a
// copy of the core settings and the agent's store set; what it needs
// from the other use cases it names as small ports of its own.
type Service struct {
	core  Core
	store StoreSet
	// pii sees every read's rows before they are returned, and every
	// write's returned rows inside the write's transaction, before it
	// commits.
	pii PIIObserver
	// update is the newer release the engine knows of, as describe's overview
	// reports it; the status use case owns it and hands it in.
	update    func() *guidance.UpdateInfo
	delivery  Delivery
	approvals Approvals
	upgrade   UpgradeWarner
	next      ApprovalLinker
	steps     Unavailable
}

// New returns the service over core and the agent's store, with the other
// use cases it asks: the delivery of held actions, the approvals, the upgrade
// warnings of run_start, the link of an approval error and the steps of an
// UNAVAILABLE error. A nil Data, Catalog or Classes is replaced by one that
// fails closed, and a nil pii by one that adds nothing; a nil Visibility
// hides nothing.
func New(core Core, store StoreSet, pii PIIObserver, update func() *guidance.UpdateInfo,
	delivery Delivery, approvals Approvals, upgrade UpgradeWarner, next ApprovalLinker, steps Unavailable,
) *Service {
	if store.Data == nil {
		store.Data = noData{}
	}
	if store.Catalog == nil {
		store.Catalog = noCatalog{}
	}
	if store.Classes == nil {
		store.Classes = noClasses{}
	}
	if pii == nil {
		pii = noPII{}
	}
	return &Service{
		core: core, store: store, pii: pii, update: update,
		delivery: delivery, approvals: approvals, upgrade: upgrade, next: next, steps: steps,
	}
}

// Family is the family of the agent's store: it picks the tools the agent
// is served.
func (ds *Service) Family() agentstore.Family { return ds.store.Family }

// noData serves a service built without the store's data: every read and
// write is an engine defect (INTERNAL), and it knows no limits.
type noData struct{}

var errNoData = errors.New("agent: no store data configured")

func (noData) Read(context.Context, agentstore.Request, action.Statement) (action.ReadResult, error) {
	return action.ReadResult{}, errNoData
}

func (noData) Write(context.Context, action.Intent, agentstore.Request, action.Statement, Returned) (action.WriteResult, error) {
	return action.WriteResult{}, errNoData
}

func (noData) WriteApproved(context.Context, action.Intent, uuid.UUID, agentstore.Request, action.Statement, Returned) (action.WriteResult, error) {
	return action.WriteResult{}, errNoData
}

func (noData) Limits() action.Limits { return action.Limits{} }
