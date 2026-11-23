package app

import (
	"context"
)

// Admit refuses a tool call the agent cannot be served yet (CONTRACT.md,
// Next steps, Startup failures): its INSTALL setup code has not run, or
// the guard is not installed or misses a breaking migration. It reads the
// guard on every call, so a guard update needs no engine restart. status is
// never refused.
// Admit is the status use case's Admit.
func (s *Service) Admit(ctx context.Context) error {
	return s.status.Admit(ctx)
}

// AdmitTick is the heartbeat's gate: it first looks for a pending setup of
// any kind in the database, so a rotated credential is picked up and
// engine.json cleared even when nobody calls status, then admits as Admit.
// AdmitTick is the status use case's AdmitTick.
func (s *Service) AdmitTick(ctx context.Context) error {
	return s.status.AdmitTick(ctx)
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
// UpdateNotice is the status use case's UpdateNotice.
func (s *Service) UpdateNotice() string {
	return s.status.UpdateNotice()
}
