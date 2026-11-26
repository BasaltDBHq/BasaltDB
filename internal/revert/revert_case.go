package revert

import (
	"context"
	"strings"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Service is the revert use case: previewing, planning, requesting, applying,
// rescoping, rejecting and revealing a revert. It holds a reference to the
// shared core group and to its own RevertDeps, holds a copy of the revert's
// store set, and owns the reverts the person
// rescoped through this engine. What it needs from the other use cases it names
// as small ports of its own.
type Service struct {
	core     Core
	store    StoreSet
	deps     *Deps
	runs     RunFinder
	delivery Delivery
	describe Describe
	admit    Admitter
	// rescopes are the reverts the person rescoped through this engine, in
	// memory only (CONTRACT.md, Rescope, widen and reject).
	rescopes *rescopes
}

// Admitter admits a call: the engine is set up and its guard is current.
type Admitter interface {
	Admit(ctx context.Context) error
}

// RunFinder looks up one run of the agent in its ledger.
type RunFinder interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
}

// Delivery is what the revert use case asks of the delivery use case.
type Delivery interface {
	AwaitWhile(ctx context.Context, wait time.Duration, pending func() bool, refresh func(context.Context) error) error
	CarriesLarge(cost int64) bool
	FieldsOf(ctx context.Context, lines []string) approval.FieldOrder
	CredentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	Deliver(n linksvc.LinkNotice)
	LargeShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, cost int64) (string, error)
	PageAddress(page func(string, uuid.UUID) string, id uuid.UUID) string
	PageLink(page func(string, uuid.UUID) string, id uuid.UUID, secret string) string
	RevertTooLargeError(id uuid.UUID, cost int64, expires time.Time) error
	ShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error)
	ShortLinked(id uuid.UUID) bool
	SignReceipt(p channel.Receipt, verb, noun string) (linksvc.Receipt, error)
	TooLargeMessage(what string, cost int64, expires time.Time, isRevert bool) string
	LinkRevoke(id uuid.UUID) error
	LinkRotate(id uuid.UUID, secret string, expires time.Time) (links.Rotated, error)
	LinkExtend(id uuid.UUID, expires time.Time) (links.RelayLink, bool, error)
	LinkReset(id uuid.UUID, until time.Time) error
	LinkWasReset(id uuid.UUID, secret string) bool
	RelayRegister(ctx context.Context, token channel.LinkToken, expires time.Time) error
	NotifyRevertTo(ctx context.Context, n linksvc.RevertNotice) error
}

// Describe is what the revert use case reads of the agent's store: the
// statement timeout its answers name.
type Describe interface {
	StatementTimeout() time.Duration
}

// New returns the service over core and the revert's store set. It panics
// on a set with a nil port, since the service reads the store only through
// them, and on a set without a prepare time limit, which a store may read
// as no limit at all.
func New(core Core, store StoreSet, deps *Deps, runs RunFinder, delivery Delivery, describe Describe, admit Admitter) *Service {
	if missing := store.missingPorts(); len(missing) > 0 {
		panic("revert: store set missing ports: " + strings.Join(missing, ", "))
	}
	if store.Limits.Prepare <= 0 {
		panic("revert: store set has no prepare time limit")
	}
	return &Service{core: core, store: store, deps: deps, runs: runs, delivery: delivery, describe: describe, admit: admit, rescopes: newRescopes()}
}

// ListOpenReverts lists the role's PENDING and APPLYING reverts, for the
// approval use case's pending list.
func (rc *Service) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	return rc.store.Records.ListOpenReverts(ctx, p)
}
