package plugin

// This file and person_plugins.go hold the engine-kept plugin entries'
// request and result types with their errors. The person socket that once
// served the person's commands in service mode is removed (CONTRACT.md, CLI,
// Removed).

// Code is an error code of an engine-kept plugin change.
type Code string

// Error codes.
const (
	CodeUIDNotAllowed   Code = "UID_NOT_ALLOWED"
	CodeUnknownAgent    Code = "UNKNOWN_AGENT"
	CodeAgentNotAllowed Code = "AGENT_NOT_ALLOWED"
	CodeUnknownMethod   Code = "UNKNOWN_METHOD"
	CodeInvalidArgument Code = "INVALID_ARGUMENT"
	CodeNotFound        Code = "NOT_FOUND"
	CodeRefused         Code = "REFUSED"
	CodeInternal        Code = "INTERNAL"
)

// PersonError is a refusal of an engine-kept plugin change, or another error of
// one, with its code.
type PersonError struct {
	Code Code `json:"code"`
	// Reason is set with CodePluginRefused only.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// Error is the message, as the same-user CLI prints the same failure.
func (e *PersonError) Error() string { return e.Message }
