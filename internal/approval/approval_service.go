package approval

import (
	"context"
	"strings"
	"time"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Service is the held writes use case: what is held for the person, the
// links that open it, the pending list and the reveal. It holds a reference to
// the shared core group and to its own Deps, and a copy of the store set it
// reads the store through. What it needs from the other use cases it names as
// small ports of its own: the delivery of links and notices, the open
// reverts, the run check, and the call admission.
type Service struct {
	core     Core
	store    StoreSet
	deps     *Deps
	delivery Delivery
	reverts  Reverts
	runs     RunChecker
	admit    Admitter
}

// Delivery is what the approval use case asks of the delivery use case.
type Delivery interface {
	ApprovalReceipt(ctx context.Context, id uuid.UUID) (linksvc.Receipt, error)
	CarriesLarge(cost int64) bool
	ColumnsOf(ctx context.Context, lines []string) approval.ColumnOrder
	CredentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	Deliver(n linksvc.LinkNotice)
	LargeShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, cost int64) (string, error)
	PageAddress(page func(string, uuid.UUID) string, id uuid.UUID) string
	PageLink(page func(string, uuid.UUID) string, id uuid.UUID, secret string) string
	ShortLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time, issue bool) (string, error)
	ShortLinked(id uuid.UUID) bool
	TooLargeMessage(what string, cost int64, expires time.Time, isRevert bool) string
}

// Reverts is what the approval use case reads of the revert use case:
// the open reverts, listed next to the held writes, and the handing over of
// a pending one.
type Reverts interface {
	ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error)
	PendingRevert(ctx context.Context, p *revertsvc.PendingRevert, reissue bool) error
}

// Admitter admits a call: the engine is set up and its guard is current.
type Admitter interface {
	Admit(ctx context.Context) error
}

// RunChecker answers whether a run is one of the agent's: NOT_FOUND when not.
type RunChecker interface {
	CheckRun(ctx context.Context, id uuid.UUID) error
}

// New builds the approval use case over core and the approval's store set.
// delivery and reverts are the other use cases it asks, and are set after
// they exist (SetDelivery, SetReverts). It panics on a set with a nil port,
// since the service reads the store only through them.
func New(core Core, store StoreSet, deps *Deps, runs RunChecker, admit Admitter) *Service {
	if missing := store.missingPorts(); len(missing) > 0 {
		panic("approval: store set missing ports: " + strings.Join(missing, ", "))
	}
	return &Service{core: core, store: store, deps: deps, runs: runs, admit: admit}
}

// SetDelivery gives the use case the delivery use case it asks.
func (ac *Service) SetDelivery(d Delivery) { ac.delivery = d }

// SetReverts gives the use case the revert use case it asks.
func (ac *Service) SetReverts(r Reverts) { ac.reverts = r }

// The reads the delivery use case makes of the approval group (approvalReads).

func (ac *Service) Passkeys(ctx context.Context) ([]passkey.Credential, error) {
	return ac.store.Records.Passkeys(ctx)
}

func (ac *Service) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	return ac.store.Records.FindApproval(ctx, id)
}

func (ac *Service) HasColumns() bool { return ac.deps.Columns != nil }

func (ac *Service) ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error) {
	return ac.deps.Columns.ColumnOrder(ctx, tables)
}

// The calls the write use case makes to hold a write.

func (ac *Service) HoldColumns(ctx context.Context, sql string, params []any) ([]string, error) {
	return ac.store.Holds.HoldColumns(ctx, sql, params)
}

func (ac *Service) Preview(ctx context.Context, in action.Intent, sql string, params []any, assigned []string) ([]string, error) {
	return ac.store.Holds.Preview(ctx, in, sql, params, assigned)
}

func (ac *Service) Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error) {
	return ac.store.Holds.Hold(ctx, in, r)
}
