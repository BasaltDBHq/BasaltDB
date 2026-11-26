// Package strictjson decodes one JSON value strictly: an unknown field or
// data after the value is refused. It is the one strict JSON reader; an
// archtest rule keeps json.Decoder.DisallowUnknownFields out of the rest of
// the module.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrTrailingData is data after the one JSON value.
var ErrTrailingData = errors.New("data after the JSON value")

// Decode decodes data into v, refusing a field v does not have and data
// after the value; whitespace after it is fine. The error is the
// decoder's, or ErrTrailingData.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Token, not More: More reports false before a stray } or ].
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTrailingData
	}
	return nil
}
