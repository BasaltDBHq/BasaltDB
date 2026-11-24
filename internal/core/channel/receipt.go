package channel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// ReceiptPrefix starts every receipt token, basalt-receipt.1.<payload>.<sig>
// (CONTRACT.md, Vault channel, Receipts).
const ReceiptPrefix = "basalt-receipt.1."

// Receipt kinds and statuses (api/mcp/vault/receipt.schema.json).
const (
	ReceiptApproval = "APPROVAL"
	ReceiptRevert   = "REVERT"

	ReceiptApproved = "APPROVED"
	ReceiptApplied  = "APPLIED"
	ReceiptApplying = "APPLYING"
)

// receiptFormat is the payload's format field.
const receiptFormat = 1

// MaxReceiptHeadline is the longest headline, in characters.
const MaxReceiptHeadline = 500

// Receipt is a receipt's payload. Field order is the order the engine
// writes; the signature covers the exact bytes, so no one needs canonical
// JSON.
type Receipt struct {
	Format   int    `json:"format"`
	Kind     string `json:"kind"`
	ItemID   string `json:"itemId"`
	Status   string `json:"status"`
	Headline string `json:"headline"`
	RowsHash string `json:"rowsHash"`
	Agent    string `json:"agent"`
	EngineID string `json:"engineId"`
	At       string `json:"at"`
	ChangeID string `json:"changeId,omitempty"`
}

var (
	receiptUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	receiptRowsHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
	receiptEngineID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	receiptAt       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// valid is the closed schema's check of a parsed payload.
func (r Receipt) Valid() bool {
	headline := utf8.RuneCountInString(r.Headline)
	_, atErr := time.Parse(time.RFC3339, r.At)
	return r.Format == receiptFormat &&
		(r.Kind == ReceiptApproval || r.Kind == ReceiptRevert) &&
		(r.Status == ReceiptApproved || r.Status == ReceiptApplied || r.Status == ReceiptApplying) &&
		receiptUUID.MatchString(r.ItemID) &&
		headline >= 1 && headline <= MaxReceiptHeadline &&
		receiptRowsHash.MatchString(r.RowsHash) &&
		r.Agent != "" &&
		receiptEngineID.MatchString(r.EngineID) &&
		atErr == nil && receiptAt.MatchString(r.At) &&
		(r.ChangeID == "" || receiptUUID.MatchString(r.ChangeID))
}

// SignReceipt signs r with the engine's key: r's engineId must be the
// signer's, and r must pass the closed schema, so the engine never hands
// out a receipt a verifier refuses.
func SignReceipt(signer Signer, r Receipt) (string, error) {
	r.Format = receiptFormat
	if r.EngineID != EngineIDOf(signer.PublicKeySPKI()) {
		return "", errors.New("vault channel: a receipt names its signer's engine id")
	}
	if !r.Valid() {
		return "", errors.New("vault channel: the receipt does not pass receipt.schema.json")
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	sig, err := signer.Sign(ContextReceipt, payload)
	if err != nil {
		return "", err
	}
	return ReceiptPrefix + b64(payload) + "." + b64(sig), nil
}
