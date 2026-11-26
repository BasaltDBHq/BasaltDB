package approval

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
)

// Delivery is what the approval use case asks of the delivery use case.
type Delivery interface {
	ApprovalReceipt(ctx context.Context, id uuid.UUID) (linksvc.Receipt, error)
	CarriesLarge(cost int64) bool
	FieldsOf(ctx context.Context, lines []string) approval.FieldOrder
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
