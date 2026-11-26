package logredact

import (
	"io"
	"log/slog"
)

// NewJSONHandler is slog.NewJSONHandler with ReplaceAttr.
func NewJSONHandler(w io.Writer, o *slog.HandlerOptions) *slog.JSONHandler {
	return slog.NewJSONHandler(w, options(o))
}
