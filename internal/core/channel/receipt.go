package channel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
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

// ErrBadReceipt is every refusal of a receipt: the verifier only says no.
var ErrBadReceipt = errors.New("vault channel: receipt refused")

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

// receiptFields are the payload's keys, true when required.
var receiptFields = map[string]bool{
	"format": true, "kind": true, "itemId": true, "status": true, "headline": true,
	"rowsHash": true, "agent": true, "engineId": true, "at": true, "changeId": false,
}

// valid is the closed schema's check of a parsed payload.
func (r Receipt) valid() bool {
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
	if !r.valid() {
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

// VerifyReceipt checks token against engineKey, the SPKI of the engine the
// verifier expects, which must come from outside the receipt (pinned, or
// the engine basalt status reports): a receipt checked only against a key
// that came with it proves nothing about which engine signed it. In the
// contract's order: the signature, then the parse, then that engineId is
// engineKey's id, then the closed schema. Every refusal is ErrBadReceipt.
// The engine only signs receipts; this is the verifier side, used by tests.
func VerifyReceipt(token string, engineKey []byte) (Receipt, error) {
	pub, err := ParseEngineKey(engineKey)
	if err != nil {
		return Receipt{}, ErrBadReceipt
	}
	rest, ok := strings.CutPrefix(token, ReceiptPrefix)
	if !ok {
		return Receipt{}, ErrBadReceipt
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return Receipt{}, ErrBadReceipt
	}
	payload, err := unb64(parts[0])
	if err != nil {
		return Receipt{}, ErrBadReceipt
	}
	sig, err := unb64(parts[1])
	if err != nil {
		return Receipt{}, ErrBadReceipt
	}
	if VerifySignature(pub, ContextReceipt, payload, sig) != nil {
		return Receipt{}, ErrBadReceipt
	}
	r, err := parseReceipt(payload)
	if err != nil {
		return Receipt{}, ErrBadReceipt
	}
	if r.EngineID != EngineIDOf(engineKey) || !r.valid() {
		return Receipt{}, ErrBadReceipt
	}
	return r, nil
}

// parseReceipt decodes a payload strictly: UTF-8, one JSON object whose
// keys are exactly the schema's (case-sensitive, none twice, none unknown).
func parseReceipt(payload []byte) (Receipt, error) {
	if !utf8.Valid(payload) {
		return Receipt{}, ErrBadReceipt
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return Receipt{}, ErrBadReceipt
	}
	if err := checkReceiptKeys(payload, raw); err != nil {
		return Receipt{}, err
	}
	var r Receipt
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || dec.More() {
		return Receipt{}, ErrBadReceipt
	}
	return r, nil
}

// checkReceiptKeys refuses a key the schema does not name, a missing
// required one, and a key given twice (json.Unmarshal keeps the last).
func checkReceiptKeys(payload []byte, raw map[string]json.RawMessage) error {
	for k, v := range raw {
		if _, ok := receiptFields[k]; !ok || string(v) == "null" || string(v) == `""` && k == "changeId" {
			return ErrBadReceipt
		}
	}
	for k, required := range receiptFields {
		if _, ok := raw[k]; required && !ok {
			return ErrBadReceipt
		}
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	if _, err := dec.Token(); err != nil { // {
		return ErrBadReceipt
	}
	keys := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return ErrBadReceipt
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return ErrBadReceipt
		}
		keys++
	}
	if keys != len(raw) {
		return ErrBadReceipt
	}
	return nil
}
