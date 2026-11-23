// Package agentmcp serves the agent's tools over MCP, and wraps every tool
// served to an agent: the admin-credential refusal, admission and the
// mapping of every error to the contract's error body.
package agentmcp

import (
	"context"
	"encoding/json"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// Gate is the served agent as wrap calls it: its error presenter, its
// admission (see Admit), and whether every personMessage carries the
// DEV_LOCAL_PAGES warning.
type Gate interface {
	Failure(tool string, args map[string]any, err error) *toolresult.ToolError
	Admit(ctx context.Context) error
	DevLocalPages() bool
}

type handlers struct {
	svc Gate
}

// Wrap is wrap for the tool list's composer: every served tool's call goes
// through it.
func Wrap(svc Gate, tool string, call func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return handlers{svc: svc}.wrap(tool, call)
}

// wrap admits the call (every tool but status, see Service.Admit) and maps
// every error to the contract's error body, logging the ones that are the
// engine's fault.
func (h handlers) wrap(tool string, call func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, args json.RawMessage) (any, error) {
		// Before anything else: the call is not admitted, decoded, recorded
		// or logged, and its arguments are not echoed into the error.
		if mcpserver.HoldsAdminCredential(args) {
			te := h.svc.Failure(tool, nil, mcpserver.AdminCredentialError())
			if h.svc.DevLocalPages() {
				return nil, linksvc.DevLocalError(te)
			}
			return nil, te
		}
		out, err := h.admitted(ctx, tool, args, call)
		switch {
		case err == nil && h.svc.DevLocalPages():
			return linksvc.DevLocalResult(out)
		case err == nil:
			return out, nil
		}
		te := h.svc.Failure(tool, guidance.CallArgs(args), err)
		if h.svc.DevLocalPages() {
			return nil, linksvc.DevLocalError(te)
		}
		return nil, te
	}
}

func (h handlers) admitted(ctx context.Context, tool string, args json.RawMessage, call func(context.Context, json.RawMessage) (any, error)) (any, error) {
	// status always answers; confirm_database answers INVALID_ARGUMENT
	// here, where no connect-only database waits (ConnectOnly serves it
	// while one does).
	if tool == guidance.ToolStatus || tool == guidance.ToolConfirmDatabase {
		return call(ctx, args)
	}
	if err := h.svc.Admit(ctx); err != nil {
		return nil, err
	}
	return call(ctx, args)
}
