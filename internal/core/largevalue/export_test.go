package largevalue

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Cost is what the value with this JSON text costs in column, measured as
// the agent's marker measures it (the store computes the same number): the
// text's bytes, EscapeCost for each byte JSON escapes, ValueOverhead and the
// field's name. jsonText is the text as the store prints it, which a
// json.RawMessage of the row's JSON keeps byte for byte.
func Cost(jsonText []byte, column string) int64 {
	var escapes int64
	for _, b := range jsonText {
		switch b {
		case '"', '\\', '<', '>', '&':
			escapes++
		}
	}
	return int64(len(jsonText)) + EscapeCost*escapes + ValueOverhead + int64(len(column))
}

// Text is the value's text as the marker hashes it: a JSON string's
// characters, anything else its JSON text.
func Text(jsonText []byte) (string, error) {
	t := bytes.TrimSpace(jsonText)
	if len(t) > 0 && t[0] == '"' {
		var s string
		if err := json.Unmarshal(t, &s); err != nil {
			return "", fmt.Errorf("largevalue: string value: %w", err)
		}
		return s, nil
	}
	return string(jsonText), nil
}
