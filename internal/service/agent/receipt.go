package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
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
func (s *Service) approvalReceipt(ctx context.Context, id uuid.UUID) (Receipt, error) {
	a, err := s.Store.FindApproval(ctx, id)
	if err != nil {
		return Receipt{}, err
	}
	return s.approvalReceiptOf(a)
}

func (s *Service) approvalReceiptOf(a action.Approval) (Receipt, error) {
	if a.Status != approvalApproved && a.Status != approvalApplied {
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
	return s.signReceipt(channel.Receipt{
		Kind: channel.ReceiptApproval, ItemID: a.ID.String(), Status: channel.ReceiptApproved,
		Headline: summary.Headline(), RowsHash: b.RowsHash,
	}, "Approved", "approval")
}

// revertReceipt is the receipt of r as Postgres shows it after the
// person's signature: APPLIED or APPLYING. A widened revert has none: the
// agent role's view holds no binding of it (RS-5).
func (s *Service) revertReceipt(r action.Revert) (Receipt, error) {
	if r.Status != revertApplied && r.Status != revertApplying {
		return Receipt{}, fmt.Errorf("revert %s is %s, not signed", r.ID, r.Status)
	}
	if r.Widened {
		return Receipt{Missing: NoReceiptWidened, Line: widenedReceiptLine(r)}, nil
	}
	b, err := revert.ParseBinding(r.BindingText)
	if err != nil {
		return Receipt{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	if b.RevertID != r.ID {
		return Receipt{}, fmt.Errorf("guard returned revert %s's binding for %s", b.RevertID, r.ID)
	}
	p := channel.Receipt{
		Kind: channel.ReceiptRevert, ItemID: r.ID.String(), Status: r.Status,
		Headline: bindingHeadline(b, r), RowsHash: b.RowsHash,
	}
	if r.ChangeID != nil {
		p.ChangeID = r.ChangeID.String()
	}
	return s.signReceipt(p, "Signed", "revert")
}

// signReceipt fills in the agent, the engine and the time and signs p
// with the engine's key. Without a usable key (KEY_ERROR) there is no
// receipt, and the line says why.
func (s *Service) signReceipt(p channel.Receipt, verb, noun string) (Receipt, error) {
	if s.Receipts == nil {
		return Receipt{Missing: NoReceiptKeyError, Line: noReceiptKeyErrorLine}, nil
	}
	p.Headline = clip(p.Headline, channel.MaxReceiptHeadline)
	p.Agent = s.Name
	p.EngineID = s.Receipts.EngineID()
	p.At = s.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	token, err := channel.SignReceipt(s.Receipts, p)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Token: token, Line: receiptLine(verb, noun, p, s.Receipts.Fingerprint())}, nil
}

// receiptLine is the person's sentence for receipt p (CONTRACT.md,
// Receipts): what was signed, by id, and the engine that says so.
func receiptLine(verb, noun string, p channel.Receipt, fingerprint string) string {
	format := func(headline string) string {
		return fmt.Sprintf("%s: %s (%s %s), receipt from engine %s.", verb, headline, noun, p.ItemID, fingerprint)
	}
	headline := strings.TrimSuffix(strings.TrimSpace(plainText(p.Headline)), ".")
	room := maxReceiptLine - len([]rune(format("")))
	return format(clip(headline, room))
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
	if r.Status == revertApplying {
		what = fmt.Sprintf("%d rows to restore in batches", r.Rows)
	}
	return "No receipt: the revert's scope was changed on the signing page (" + what + "). If you did not change it, tell the agent at once."
}
