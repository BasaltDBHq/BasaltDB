package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
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

// liveApprovals reads the approval group as it stands when asked.
type liveApprovals struct{ d *ApprovalDeps }

func (l liveApprovals) Passkeys(ctx context.Context) ([]passkey.Credential, error) {
	return l.d.Store.Passkeys(ctx)
}

func (l liveApprovals) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	return l.d.Store.FindApproval(ctx, id)
}

func (l liveApprovals) hasColumns() bool { return l.d.Columns != nil }

func (l liveApprovals) ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error) {
	return l.d.Columns.ColumnOrder(ctx, tables)
}

func newDeliveryCase(core *CoreDeps, deps *DeliveryDeps, approvals approvalReads,
	failure func(tool string, args map[string]any, err error) *toolresult.ToolError,
) *deliveryCase {
	return &deliveryCase{core: core, deps: deps, approvals: approvals, failure: failure}
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
