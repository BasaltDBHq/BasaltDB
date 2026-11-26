package channeltest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
)

// ErrBadReceipt is every refusal of a receipt: the verifier only says no.
var ErrBadReceipt = errors.New("vault channel: receipt refused")

// receiptFields are the payload's keys, true when required.
var receiptFields = map[string]bool{
	"format": true, "kind": true, "itemId": true, "status": true, "headline": true,
	"rowsHash": true, "agent": true, "engineId": true, "at": true, "changeId": false,
}

// VerifyReceipt checks token against engineKey, the SPKI of the engine the
// verifier expects, which must come from outside the receipt (pinned, or
// the engine basalt status reports): a receipt checked only against a key
// that came with it proves nothing about which engine signed it. In the
// contract's order: the signature, then the parse, then that engineId is
// engineKey's id, then the closed schema. Every refusal is ErrBadReceipt.
// The engine only signs receipts; this is the verifier side, used by tests.
func VerifyReceipt(token string, engineKey []byte) (channel.Receipt, error) {
	pub, err := channel.ParseEngineKey(engineKey)
	if err != nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	rest, ok := strings.CutPrefix(token, channel.ReceiptPrefix)
	if !ok {
		return channel.Receipt{}, ErrBadReceipt
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return channel.Receipt{}, ErrBadReceipt
	}
	payload, err := channel.Unb64(parts[0])
	if err != nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	sig, err := channel.Unb64(parts[1])
	if err != nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	if channel.VerifySignature(pub, channel.ContextReceipt, payload, sig) != nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	r, err := parseReceipt(payload)
	if err != nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	if r.EngineID != channel.EngineIDOf(engineKey) || !r.Valid() {
		return channel.Receipt{}, ErrBadReceipt
	}
	return r, nil
}

// parseReceipt decodes a payload strictly: UTF-8, one JSON object whose
// keys are exactly the schema's (case-sensitive, none twice, none unknown).
func parseReceipt(payload []byte) (channel.Receipt, error) {
	if !utf8.Valid(payload) {
		return channel.Receipt{}, ErrBadReceipt
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return channel.Receipt{}, ErrBadReceipt
	}
	if err := checkReceiptKeys(payload, raw); err != nil {
		return channel.Receipt{}, err
	}
	var r channel.Receipt
	if err := strictjson.Decode(payload, &r); err != nil {
		return channel.Receipt{}, ErrBadReceipt
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
