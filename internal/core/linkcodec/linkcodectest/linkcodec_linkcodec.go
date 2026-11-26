package linkcodectest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Encode returns a fragment (without '#'): format, then the base64url of
// the deflate-raw of v's JSON.
func Encode(format string, v any) (string, error) {
	raw, err := linkcodec.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	return linkcodec.Deflate(format, raw)
}

// Split returns the payload of a format 2 fragment, with or without '#'.
func Split(fragment string) (payload string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimPrefix(fragment, "#"), linkcodec.Format2)
	if !ok {
		return "", fmt.Errorf("must start with %q", linkcodec.Format2)
	}
	return rest, nil
}

// DecodeRequest decodes a format 2 request fragment, with or without '#'.
// It rebuilds the binding text and at most maxLines lines and hands them, with the
// credential ids it carries (nil for none), to expand. The caller still
// checks the request against its binding.
func DecodeRequest[R any](fragment string, maxLines int, expand func(binding string, lines []string, ids []passkey.Bytes) R) (R, error) {
	var zero R
	payload, err := Split(fragment)
	if err != nil {
		return zero, err
	}
	var c linkcodec.Lines
	if err := linkcodec.Decode(payload, &c); err != nil {
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
