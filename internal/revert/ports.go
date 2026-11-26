package revert

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

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
