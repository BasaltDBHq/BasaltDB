package links

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Service is how a held write, a revert or a plugin approval reaches the
// person: the notices, the short links, the receipts and the page links. It
// holds a copy of the settings it reads (Core) and a reference to its own Deps.
// What it reads from the approval use case and from the error mapping it names
// as small ports of its own.
type Service struct {
	core Core
	deps *Deps
	// approvals is what delivery reads of the approval use case: the person's
	// passkeys (the credentials a signing link accepts), an approval to receipt,
	// and each resource's field order for the pages.
	approvals ApprovalReads
	// failure maps an error to the tool's error body for a page answer.
	failure func(tool string, args map[string]any, err error) *toolresult.ToolError
}

func New(core Core, deps *Deps, approvals ApprovalReads,
	failure func(tool string, args map[string]any, err error) *toolresult.ToolError,
) *Service {
	return &Service{core: core, deps: deps, approvals: approvals, failure: failure}
}

// The calls the revert use case makes on the links and the relay, which
// delivery owns.

func (dc *Service) LinkRevoke(id uuid.UUID) error { return dc.deps.Links.RevokeItem(id) }

func (dc *Service) LinkRotate(id uuid.UUID, secret string, expires time.Time) (links.Rotated, error) {
	return dc.deps.Links.Rotate(id, secret, expires)
}

func (dc *Service) LinkExtend(id uuid.UUID, expires time.Time) (links.RelayLink, bool, error) {
	return dc.deps.Links.Extend(id, expires)
}

func (dc *Service) LinkReset(id uuid.UUID, until time.Time) error {
	return dc.deps.Links.Reset(id, until)
}

func (dc *Service) LinkWasReset(id uuid.UUID, secret string) bool {
	return dc.deps.Links.WasReset(id, secret)
}

func (dc *Service) RelayRegister(ctx context.Context, token channel.LinkToken, expires time.Time) error {
	return dc.deps.Relay.Register(ctx, token, expires)
}

func (dc *Service) NotifyRevertTo(ctx context.Context, n RevertNotice) error {
	return dc.deps.Notifier.NotifyRevert(ctx, n)
}

func (dc *Service) NotifyHeldTo(ctx context.Context, n HeldNotice) error {
	return dc.deps.Notifier.NotifyHeld(ctx, n)
}

func (dc *Service) RelayConnected() bool { return dc.deps.Relay.Connected() }

func (dc *Service) PollInterval() time.Duration { return dc.deps.Poll }
