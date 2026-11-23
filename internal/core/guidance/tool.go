package guidance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// Tool is one tool the agent serves: its listing and its handler. The
// inbound adapter turns it into the protocol's own tool (its fields match,
// so a conversion carries them over). InputSchema is the JSON Schema of the
// arguments. Call returns a value rendered as JSON text, or an error; a
// *toolresult.ToolError keeps its code on the wire.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Call        func(ctx context.Context, args json.RawMessage) (any, error)
}

// CallArgs are the arguments of a call, as the engine reads them back into
// the next steps of its error (a repeated call merges over them). Numbers
// keep their text; a call whose arguments are not an object has none.
func CallArgs(raw json.RawMessage) map[string]any {
	var args map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&args) != nil {
		return nil
	}
	return args
}

var validate = validator.New(validator.WithRequiredStructEnabled())

// DecodeArgs decodes tool arguments strictly: unknown arguments are refused,
// numbers keep their text, and struct tags are validated.
func DecodeArgs(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return &ArgumentError{Message: fmt.Sprintf("invalid arguments: %v", err)}
	}
	if err := validate.Struct(v); err != nil {
		return &ArgumentError{Message: fmt.Sprintf("invalid arguments: %v", err)}
	}
	return nil
}

// TimeText is a time as the tools state it: UTC, RFC 3339.
func TimeText(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
