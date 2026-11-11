package apperrors

import (
	"encoding/json"
	"errors"
	"net/http"
)

const problemType = "about:blank"

// AppError is the shared HTTP-facing error type. Handlers return it (or an
// error it wraps); the central writer maps Status to the response code.
type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	Err     error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *AppError) Unwrap() error { return e.Err }

func NotFound(msg string) *AppError {
	return &AppError{Code: "NOT_FOUND", Message: msg, Status: http.StatusNotFound}
}

func BadRequest(msg string) *AppError {
	return &AppError{Code: "BAD_REQUEST", Message: msg, Status: http.StatusBadRequest}
}

func UnknownQueryParam(msg string) *AppError {
	return &AppError{Code: "UNKNOWN_QUERY_PARAM", Message: msg, Status: http.StatusBadRequest}
}

func Validation(msg string) *AppError {
	return &AppError{Code: "VALIDATION_ERROR", Message: msg, Status: http.StatusUnprocessableEntity}
}

func PreconditionRequired(msg string) *AppError {
	return &AppError{Code: "PRECONDITION_REQUIRED", Message: msg, Status: http.StatusPreconditionRequired}
}

func Conflict(msg string) *AppError {
	return &AppError{Code: "CONFLICT", Message: msg, Status: http.StatusConflict}
}

func Forbidden(msg string) *AppError {
	return &AppError{Code: "FORBIDDEN", Message: msg, Status: http.StatusForbidden}
}

func Unauthorized(msg string) *AppError {
	return &AppError{Code: "UNAUTHORIZED", Message: msg, Status: http.StatusUnauthorized}
}

func PreconditionFailed(msg string) *AppError {
	return &AppError{Code: "PRECONDITION_FAILED", Message: msg, Status: http.StatusPreconditionFailed}
}

func RateLimited(msg string) *AppError {
	return &AppError{Code: "RATE_LIMITED", Message: msg, Status: http.StatusTooManyRequests}
}

func ServiceUnavailable(msg string) *AppError {
	return &AppError{Code: "UNAVAILABLE", Message: msg, Status: http.StatusServiceUnavailable}
}

// PluginFailed is a write refused by a PRE_WRITE plugin the collection turned on (Plan 4).
func PluginFailed(msg string, err error) *AppError {
	return &AppError{Code: "PLUGIN_FAILED", Message: msg, Status: http.StatusUnprocessableEntity, Err: err}
}

// PluginOff is a request that needs a plugin the collection doesn't have on (Plan 4).
func PluginOff(msg string) *AppError {
	return &AppError{Code: "PLUGIN_OFF", Message: msg, Status: http.StatusUnprocessableEntity}
}

func Internal(msg string, err error) *AppError {
	return &AppError{Code: "INTERNAL", Message: msg, Status: http.StatusInternalServerError, Err: err}
}

// Status returns the HTTP status for err, defaulting to 500.
func Status(err error) int {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return http.StatusInternalServerError
}

// Problem is RFC 9457 problem+json with Basalt code extension.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
}

func problemTitle(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "Not Found"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusPreconditionFailed:
		return "Precondition Failed"
	case http.StatusPreconditionRequired:
		return "Precondition Required"
	case http.StatusUnprocessableEntity:
		return "Unprocessable Entity"
	case http.StatusTooManyRequests:
		return "Too Many Requests"
	case http.StatusServiceUnavailable:
		return "Service Unavailable"
	}
	if t := http.StatusText(status); t != "" {
		return t
	}
	return "Internal Server Error"
}

func toProblem(ae *AppError) Problem {
	return Problem{
		Type:   problemType,
		Title:  problemTitle(ae.Status),
		Status: ae.Status,
		Detail: ae.Message,
		Code:   ae.Code,
	}
}

// WriteJSON writes err as application/problem+json.
func WriteJSON(w http.ResponseWriter, err error) {
	var ae *AppError
	if !errors.As(err, &ae) {
		ae = Internal(err.Error(), err)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(ae.Status)
	if encErr := json.NewEncoder(w).Encode(toProblem(ae)); encErr != nil {
		_ = encErr
	}
}
