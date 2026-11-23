package agent

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// revertReceipt is the receipt of r as Postgres shows it after the
// person's signature: APPLIED or APPLYING. A widened revert has none: the
// agent role's view holds no binding of it (RS-5).
func (rc *revertCase) revertReceipt(r action.Revert) (Receipt, error) {
	if r.Status != action.RevertApplied && r.Status != action.RevertApplying {
		return Receipt{}, fmt.Errorf("revert %s is %s, not signed", r.ID, r.Status)
	}
	if r.Widened {
		return Receipt{Missing: NoReceiptWidened, Line: WidenedReceiptLine(r)}, nil
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
	return rc.delivery.SignReceipt(p, "Signed", "revert")
}
