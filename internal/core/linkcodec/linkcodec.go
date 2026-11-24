// Package linkcodec encodes and decodes the request a long approval or
// revert link carries in its fragment (CONTRACT.md, Codes):
//
//	1.<base64url(deflate-raw(request JSON))>   format 1, read only
//	2.<base64url(deflate-raw(compact JSON))>   format 2, what the engine emits
//
// Format 2 carries the preview or revert lines as shapes and values (Lines)
// that the page rebuilds to the exact line text before hashing. Links are
// untrusted input: every length is capped, and anything after the deflate
// stream or after the JSON value is refused.
package linkcodec

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Fragment formats: the prefix after '#'.
const (
	Format1 = "1."
	Format2 = "2."
)

const (
	// MaxFragmentLen caps the base64url payload before decoding.
	MaxFragmentLen = 1 << 20
	// MaxInflatedBytes caps the inflated JSON, so a crafted link cannot
	// inflate without bound.
	MaxInflatedBytes = 1 << 20
)

var errTrailing = errors.New("has data after its end")

// deflate returns format, then the base64url of the deflate-raw of raw.
func Deflate(format string, raw []byte) (string, error) {
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
	return format + passkey.Bytes(buf.Bytes()).String(), nil
}

// marshal is json.Marshal without HTML escaping: the JSON only travels in a
// fragment, and < is six bytes where < is one.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Split returns the format and the payload of a fragment, with or without
// '#'.
func Split(fragment string) (format, payload string, err error) {
	text := strings.TrimPrefix(fragment, "#")
	for _, f := range []string{Format1, Format2} {
		if rest, ok := strings.CutPrefix(text, f); ok {
			return f, rest, nil
		}
	}
	return "", "", fmt.Errorf("must start with %q or %q", Format1, Format2)
}

// Decode decodes a payload into v: base64url, then deflate-raw with nothing
// after the end of its stream, then at most MaxInflatedBytes of UTF-8 JSON
// holding one value with only v's fields and nothing after it.
func Decode(payload string, v any) error {
	if len(payload) > MaxFragmentLen {
		return fmt.Errorf("longer than %d bytes", MaxFragmentLen)
	}
	// RawURLEncoding skips line breaks; a link has none.
	if strings.ContainsAny(payload, "\r\n") {
		return errors.New("is not base64url")
	}
	compressed, err := passkey.DecodeBase64URL(payload)
	if err != nil {
		return errors.New("is not base64url")
	}
	raw, err := inflate(compressed)
	if err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errors.New("is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("is not a request: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON %w", errTrailing)
	}
	return nil
}

// inflate reads one deflate-raw stream of at most MaxInflatedBytes and
// refuses bytes after its end. flate reads a bytes.Reader (an
// io.ByteReader) no further than the stream's last byte.
func inflate(compressed []byte) ([]byte, error) {
	src := bytes.NewReader(compressed)
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(src), MaxInflatedBytes+1))
	if err != nil {
		return nil, errors.New("is not deflate-raw")
	}
	if len(raw) > MaxInflatedBytes {
		return nil, fmt.Errorf("inflates past %d bytes", MaxInflatedBytes)
	}
	if src.Len() != 0 {
		return nil, fmt.Errorf("deflate stream %w", errTrailing)
	}
	return raw, nil
}

// EncodeRequest returns the format 2 fragment (without '#') for a binding
// text and its lines: the compact form of the binding followed by the
// lines, and the database's credential ids when there are any (at most
// MaxCredentialIDs).
//
// It returns ErrRequestTooLarge when a page would refuse the fragment: its
// texts rebuild past MaxLinesBytes, its JSON past MaxInflatedBytes, or its
// payload past MaxFragmentLen (CONTRACT.md, Format 2, Limits).
func EncodeRequest(binding string, lines []string, ids []passkey.Bytes) (string, error) {
	if len(ids) > MaxCredentialIDs {
		return "", fmt.Errorf("encode request: %d credential ids, at most %d", len(ids), MaxCredentialIDs)
	}
	total := len(binding)
	for _, l := range lines {
		total += len(l)
	}
	if total > MaxLinesBytes {
		return "", fmt.Errorf("%w: its texts are %d bytes, at most %d", ErrRequestTooLarge, total, MaxLinesBytes)
	}
	c := Compact(append([]string{binding}, lines...))
	c.CredentialIDs = ids
	raw, err := Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	if len(raw) > MaxInflatedBytes {
		return "", fmt.Errorf("%w: its JSON is %d bytes, at most %d", ErrRequestTooLarge, len(raw), MaxInflatedBytes)
	}
	frag, err := Deflate(Format2, raw)
	if err != nil {
		return "", err
	}
	if n := len(frag) - len(Format2); n > MaxFragmentLen {
		return "", fmt.Errorf("%w: its payload is %d characters, at most %d", ErrRequestTooLarge, n, MaxFragmentLen)
	}
	return frag, nil
}

// ErrRequestTooLarge is a request too large for any link: a page would
// refuse to decode it. Only a short link to pages that fetch the request
// from the engine can carry it (CONTRACT.md, Large values).
var ErrRequestTooLarge = errors.New("the request is too large for a link")

// DecodeRequest decodes a request fragment of either format, with or
// without '#'. Format 1 decodes into R as it is. Format 2 rebuilds the
// binding text and at most maxLines lines and hands them, with the
// credential ids it carries (nil for none), to expand. The caller still
// checks the request against its binding.
func DecodeRequest[R any](fragment string, maxLines int, expand func(binding string, lines []string, ids []passkey.Bytes) R) (R, error) {
	var zero R
	format, payload, err := Split(fragment)
	if err != nil {
		return zero, err
	}
	if format == Format1 {
		var r R
		if err := Decode(payload, &r); err != nil {
			return zero, err
		}
		return r, nil
	}
	var c Lines
	if err := Decode(payload, &c); err != nil {
		return zero, err
	}
	// The binding travels as the first text.
	switch {
	case len(c.Lines) < 2:
		return zero, errors.New("has no lines after its binding")
	case len(c.Lines) > maxLines+1:
		return zero, fmt.Errorf("has %d lines, at most %d", len(c.Lines)-1, maxLines)
	}
	lines, err := c.Rebuild(maxLines + 1)
	if err != nil {
		return zero, err
	}
	return expand(lines[0], lines[1:], c.CredentialIDs), nil
}
