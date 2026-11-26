package agent

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Core is the part of the shared settings the agent use cases read, copied
// when the service is built.
type Core struct {
	Name     string
	Log      *slog.Logger
	Now      func() time.Time
	Commands guidance.Commands
	Errors   guidance.ErrorMap
}
