package approval

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// EncodeFragment returns a link fragment (without '#') for a request payload:
// RequestPrefix + base64url(deflate-raw(json)). Approval and revert links
// share it (CONTRACT.md, Approvals and Revert).
func EncodeFragment(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("deflate request: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return "", fmt.Errorf("deflate request: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("deflate request: %w", err)
	}
	return RequestPrefix + passkey.Bytes(buf.Bytes()).String(), nil
}

// DecodeFragment decodes a link fragment, with or without '#', into v,
// refusing unknown fields, oversized input and inflation bombs. what names
// the payload in errors ("approval request"). Every error wraps ErrInvalid.
func DecodeFragment(fragment, what string, v any) error {
	payload, ok := strings.CutPrefix(strings.TrimPrefix(fragment, "#"), RequestPrefix)
	if !ok {
		return invalid("%s must start with %q", what, RequestPrefix)
	}
	if len(payload) > maxFragmentLen {
		return invalid("%s longer than %d bytes", what, maxFragmentLen)
	}
	compressed, err := passkey.DecodeBase64URL(payload)
	if err != nil {
		return invalid("%s is not base64url", what)
	}
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), maxRequestBytes+1))
	if err != nil {
		return invalid("%s is not deflate-raw", what)
	}
	if len(raw) > maxRequestBytes {
		return invalid("%s inflates past %d bytes", what, maxRequestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("%s: %v", what, err)
	}
	return nil
}
