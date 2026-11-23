package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// ReceiptSigner is the engine's signing key (*channel.EngineKeys), which
// signs the receipt of every signature the engine relays (CONTRACT.md,
// Vault channel, Receipts).
type ReceiptSigner interface {
	channel.Signer
	EngineID() string
	Fingerprint() string
}

// Why a signed item's answer carries no receipt (noReceipt).
const (
	NoReceiptKeyError = "KEY_ERROR"
	NoReceiptWidened  = "WIDENED"
)

// The receipt lines without a receipt (CONTRACT.md, Receipts).
const (
	noReceiptKeyErrorLine = "No receipt: the engine's key file is refused (Basalt's status reports KEY_ERROR), so nothing confirms what was signed."
)

// maxReceiptLine bounds the receipt line, so the rest of a personMessage
// fits beside it.
const maxReceiptLine = 300

// Receipt is the engine-signed receipt of a signed item, or why there is
// none, with the line the person is shown.
type Receipt struct {
	// Token is basalt-receipt.1.<payload>.<sig>; empty with Missing.
	Token string
	// Missing is NoReceiptKeyError or NoReceiptWidened when there is none.
	Missing string
	// Line is the receipt line for personMessage.
	Line string
}

// approvalReceipt reads approval id from Postgres, after the person's
// signature was accepted, and signs its receipt. Only an approved (or
// already applied) approval gets one.
func (dc *deliveryCase) approvalReceipt(ctx context.Context, id uuid.UUID) (Receipt, error) {
	a, err := dc.approvals.FindApproval(ctx, id)
	if err != nil {
		return Receipt{}, err
	}
	return dc.approvalReceiptOf(a)
}

func (dc *deliveryCase) approvalReceiptOf(a action.Approval) (Receipt, error) {
	if a.Status != action.ApprovalApproved && a.Status != action.ApprovalApplied {
		return Receipt{}, fmt.Errorf("approval %s is %s, not signed", a.ID, a.Status)
	}
	b, err := approval.ParseBinding(a.BindingText)
	if err != nil {
		return Receipt{}, fmt.Errorf("guard returned a bad approval binding: %w", err)
	}
	if b.ApprovalID != a.ID {
		return Receipt{}, fmt.Errorf("guard returned approval %s's binding for %s", b.ApprovalID, a.ID)
	}
	summary, err := approval.SummarizeText(a.Lines)
	if err != nil {
		return Receipt{}, err
	}
	return dc.signReceipt(channel.Receipt{
		Kind: channel.ReceiptApproval, ItemID: a.ID.String(), Status: channel.ReceiptApproved,
		Headline: summary.Headline(), RowsHash: b.RowsHash,
	}, "Approved", "approval")
}

// signReceipt fills in the agent, the engine and the time and signs p
// with the engine's key. Without a usable key (KEY_ERROR) there is no
// receipt, and the line says why.
func (dc *deliveryCase) signReceipt(p channel.Receipt, verb, noun string) (Receipt, error) {
	if dc.deps.Receipts == nil {
		return Receipt{Missing: NoReceiptKeyError, Line: noReceiptKeyErrorLine}, nil
	}
	p.Headline = guidance.Clip(p.Headline, channel.MaxReceiptHeadline)
	p.Agent = dc.core.Name
	p.EngineID = dc.deps.Receipts.EngineID()
	p.At = dc.core.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	token, err := channel.SignReceipt(dc.deps.Receipts, p)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Token: token, Line: receiptLine(verb, noun, p, dc.deps.Receipts.Fingerprint())}, nil
}

// receiptLine is the person's sentence for receipt p (CONTRACT.md,
// Receipts): what was signed, by id, and the engine that says so.
func receiptLine(verb, noun string, p channel.Receipt, fingerprint string) string {
	format := func(headline string) string {
		return fmt.Sprintf("%s: %s (%s %s), receipt from engine %s.", verb, headline, noun, p.ItemID, fingerprint)
	}
	headline := strings.TrimSuffix(strings.TrimSpace(guidance.PlainText(p.Headline)), ".")
	room := maxReceiptLine - len([]rune(format("")))
	return format(guidance.Clip(headline, room))
}

// withReceiptLine puts the receipt line first in a personMessage.
func withReceiptLine(line, message string) string {
	if message == "" {
		return line
	}
	return line + "\n" + message
}

// widenedReceiptLine is the line of a widened revert, which has no
// receipt (provisional, CONTRACT.md, Receipts): the totals the agent may
// see, and what to do if the person did not widen it.
func widenedReceiptLine(r action.Revert) string {
	what := fmt.Sprintf("%d rows restored", r.Rows)
	if r.Status == action.RevertApplying {
		what = fmt.Sprintf("%d rows to restore in batches", r.Rows)
	}
	return "No receipt: the revert's scope was changed on the signing page (" + what + "). If you did not change it, tell the agent at once."
}
