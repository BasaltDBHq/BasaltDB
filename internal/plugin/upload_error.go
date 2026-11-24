package plugin

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// UploadError is the upload methods' answer for err.
func UploadError(err error) *toolresult.ToolError {
	var te *toolresult.ToolError
	var r *PluginRefusedError
	var ae *guidance.ArgumentError
	switch {
	case errors.As(err, &te):
		return te
	case errors.As(err, &r):
		return &toolresult.ToolError{Code: "PLUGIN_REFUSED", Reason: r.Reason, Message: r.Message}
	case errors.As(err, &ae):
		return &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: ae.Message}
	case errors.Is(err, ErrPluginNotFound):
		return &toolresult.ToolError{Code: guidance.CodeNotFound, Message: "the upload is unknown, expired or used"}
	}
	return &toolresult.ToolError{Code: guidance.CodeInternal, Message: "the engine could not take the plugin's files"}
}
