package agent

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// deliveryCase is how a held write, a revert or a plugin approval reaches the
// person: the notices, the short links, the receipts and the page links. It
// holds the shared core group and its own DeliveryDeps. What it reads from the
// approval use case and from the error mapping it names as small ports of
// its own, which the service wires when it is built.
type deliveryCase struct {
	core *CoreDeps
	deps *DeliveryDeps
	// approvals is what delivery reads of the approval use case: the person's
	// passkeys (the credentials a signing link accepts), an approval to receipt,
	// and each table's column order for the pages.
	approvals approvalReads
	// failure maps an error to the tool's error body for a page answer.
	failure func(tool string, args map[string]any, err error) *toolresult.ToolError
}

// approvalReads is the part of the approval group that delivery reads.
type approvalReads interface {
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
	FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error)
	// hasColumns says whether the pages can show the tables' column order.
	hasColumns() bool
	ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error)
}

func newDeliveryCase(core *CoreDeps, deps *DeliveryDeps,
	failure func(tool string, args map[string]any, err error) *toolresult.ToolError,
) *deliveryCase {
	return &deliveryCase{core: core, deps: deps, failure: failure}
}

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

// The calls the revert use case makes on the links and the relay, which
// delivery owns.

func (dc *deliveryCase) LinkRevoke(id uuid.UUID) error { return dc.deps.Links.RevokeItem(id) }

func (dc *deliveryCase) LinkRotate(id uuid.UUID, secret string, expires time.Time) (links.Rotated, error) {
	return dc.deps.Links.Rotate(id, secret, expires)
}

func (dc *deliveryCase) LinkExtend(id uuid.UUID, expires time.Time) (links.RelayLink, bool, error) {
	return dc.deps.Links.Extend(id, expires)
}

func (dc *deliveryCase) LinkReset(id uuid.UUID, until time.Time) error {
	return dc.deps.Links.Reset(id, until)
}

func (dc *deliveryCase) LinkWasReset(id uuid.UUID, secret string) bool {
	return dc.deps.Links.WasReset(id, secret)
}

func (dc *deliveryCase) RelayRegister(ctx context.Context, token channel.LinkToken, expires time.Time) error {
	return dc.deps.Relay.Register(ctx, token, expires)
}

func (dc *deliveryCase) NotifyRevertTo(ctx context.Context, n RevertNotice) error {
	return dc.deps.Notifier.NotifyRevert(ctx, n)
}

func (dc *deliveryCase) NotifyHeldTo(ctx context.Context, n HeldNotice) error {
	return dc.deps.Notifier.NotifyHeld(ctx, n)
}

func (dc *deliveryCase) RelayConnected() bool { return dc.deps.Relay.Connected() }

func (dc *deliveryCase) PollInterval() time.Duration { return dc.deps.Poll }
