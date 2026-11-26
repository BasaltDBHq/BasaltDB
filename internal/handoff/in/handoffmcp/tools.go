// Package handoffmcp serves the hand-off's tools over MCP: confirm_database
// on a served agent, where no connect-only database waits.
package handoffmcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// confirmArgs are confirm_database's arguments.
type confirmArgs struct {
	SetupID  string            `json:"setupId" validate:"required,uuid"`
	Database setupcode.Address `json:"database" validate:"required"`
	Answer   string            `json:"answer" validate:"required,oneof=YES NO"`
}

// --- the served agent's confirm_database ---

// Confirmer confirms the database a connect-only setup collected, as
// confirm_database calls it. On a served agent no such database waits: it
// answers handoff.ErrNotWaiting.
type Confirmer interface {
	ConfirmDatabase(ctx context.Context, setupID string, db setupcode.Address, yes bool) (handoff.ConfirmResult, error)
}

type handlers struct {
	svc Confirmer
}

// confirmDatabase answers confirm_database; a database that does not wait
// is INVALID_ARGUMENT.
func (h handlers) confirmDatabase(ctx context.Context, raw json.RawMessage) (any, error) {
	var args confirmArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	res, err := h.svc.ConfirmDatabase(ctx, args.SetupID, args.Database, args.Answer == handoff.AnswerYes)
	switch {
	case errors.Is(err, handoff.ErrNotWaiting):
		return nil, &guidance.ArgumentError{Message: err.Error()}
	case err != nil:
		return nil, err
	}
	return res, nil
}

// Tools are the tools that confirm the collected database. mount lists a
// tool under its contract, around the agent's admission and error mapping;
// the tool list's composer supplies it.
func Tools(svc Confirmer, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc}
	return []mcpserver.Tool{
		mount(guidance.ToolConfirmDatabase, h.confirmDatabase),
	}
}
