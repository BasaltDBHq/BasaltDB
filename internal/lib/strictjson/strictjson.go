// Package strictjson decodes one JSON value strictly: an unknown field or
// data after the value is refused.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ErrTrailingData is data after the one JSON value.
var ErrTrailingData = errors.New("data after the JSON value")

// Decode decodes data into v, refusing a field v does not have and data
// after the value. The error is the decoder's, or ErrTrailingData.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return ErrTrailingData
	}
	return nil
}
